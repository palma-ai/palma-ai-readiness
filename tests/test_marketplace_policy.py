"""Offline provenance joins and priority calibration; all homes are synthetic."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from palma_scan.collector import collect
from palma_scan.rules import evaluate


class MarketplacePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve() / 'home'
        self.home.mkdir()

    def write(self, path, data):
        target = self.home / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data if isinstance(data, str) else json.dumps(data))
        return target

    def plugin(self, client, market, name='example'):
        base = f'.{client}/plugins/cache/{market}/{name}/1.0.0'
        self.write(base + f'/.{client}-plugin/plugin.json', {'name': name, 'version': '1.0.0'})
        self.write(base + '/skills/example/SKILL.md', '---\nname: example\ndescription: Fixture only\n---\nExample instructions.')
        return base

    def scan(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no process')), patch('socket.socket', side_effect=AssertionError('no network')):
            result = collect(self.home, scope_type='copied-home')
        result['findings'] = evaluate(result)
        return result

    def artifacts(self, result):
        return [x for x in result['observations'] if x['kind'] in {'plugin', 'skill'} and x['details'].get('activation') != 'configured']

    def test_claude_official_source_join_makes_only_provenance_informational(self):
        base = self.plugin('claude', 'claude-plugins-official')
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write(base + '/.mcp.json', {'mcpServers': {'example': {'command': 'node', 'env': {'API_KEY': 'fixture-credential-123456789'}}}})
        result = self.scan()
        self.assertTrue(self.artifacts(result))
        self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(result)))
        ids = {x['id'] for x in self.artifacts(result)}
        origin_findings = [x for x in result['findings'] if ids.intersection(x['observationIds'])]
        self.assertTrue(origin_findings)
        self.assertTrue(all(x['severity'] == 'info' for x in origin_findings))
        self.assertTrue(any(x['ruleId'] == 'mcp-inline-credential' and x['severity'] == 'critical' for x in result['findings']))
        self.assertTrue(all(x['details']['auditStatus'] == 'not-assessed' for x in self.artifacts(result)))

    def test_official_marketplace_label_without_origin_does_not_establish_trust(self):
        self.plugin('claude', 'claude-plugins-official')
        result = self.scan()
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unresolved' for x in self.artifacts(result)))
        ids = {x['id'] for x in self.artifacts(result)}
        self.assertTrue(any(x['severity'] == 'critical' and ids <= set(x['observationIds']) for x in result['findings']))

    def test_lookalike_and_url_tricks_do_not_match_an_allowlisted_origin(self):
        self.plugin('claude', 'claude-plugins-official')
        origins = [
            {'source': 'github', 'repo': 'other/claude-plugins-official'},
            {'source': 'github', 'repo': 'anthropics/claude-plugins-official/extra'},
            {'source': 'github', 'repo': 'anthropics/claude-plugins-official', 'path': 'unreviewed'},
            {'source': 'git', 'url': 'https://github.com.evil.test/anthropics/claude-plugins-official'},
            {'source': 'git', 'url': 'https://github.com@evil.test/anthropics/claude-plugins-official'},
            {'source': 'git', 'url': 'https://github.com/anthropics/claude-plugins-official?url=official'},
            {'source': 'git', 'url': 'https://github.com/anthropics/claude-plugins-official/tree/main'},
            {'source': 'directory', 'path': '/not-read/claude-plugins-official'},
        ]
        for origin in origins:
            with self.subTest(origin=origin):
                self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': origin}})
                self.assertTrue(all(x['details'].get('sourceTrust') == 'unapproved' for x in self.artifacts(self.scan())))

    def test_codex_git_marketplace_uses_exact_configured_origin(self):
        self.plugin('codex', 'company-alias')
        self.write('.codex/config.toml', '[marketplaces.company-alias]\nsource_type="git"\nsource="https://github.com/openai/plugins.git"\n')
        result = self.scan()
        self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(result)))
        self.assertTrue(all(x['details'].get('sourcePolicyId') == 'openai-plugins' for x in self.artifacts(result)))

    def test_codex_remote_requires_install_record_and_rejects_source_override(self):
        self.plugin('codex', 'openai-curated-remote')
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unresolved' for x in self.artifacts(self.scan())))
        metadata = '.codex/plugins/cache/openai-curated-remote/example/.codex-remote-plugin-install.json'
        self.write(metadata, {'schema_version': 1, 'remote_plugin_id': 'plugin_fixture'})
        self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(self.scan())))
        self.write('.codex/config.toml', '[marketplaces.openai-curated-remote]\nsource_type="git"\nsource="https://github.com/unapproved/plugins.git"\n')
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unapproved' for x in self.artifacts(self.scan())))

    def test_remote_metadata_wrong_shape_or_symlink_cannot_establish_trust(self):
        self.plugin('codex', 'openai-curated-remote')
        metadata = '.codex/plugins/cache/openai-curated-remote/example/.codex-remote-plugin-install.json'
        for data in ({'schema_version': True, 'remote_plugin_id': 'plugin_fixture'}, {'schema_version': 2, 'remote_plugin_id': 'plugin_fixture'}, {'schema_version': 1, 'remote_plugin_id': ''}):
            self.write(metadata, data)
            self.assertTrue(all(x['details'].get('sourceTrust') != 'allowlisted' for x in self.artifacts(self.scan())))
        target = self.write('outside.json', {'schema_version': 1, 'remote_plugin_id': 'plugin_fixture'})
        (self.home / metadata).unlink()
        (self.home / metadata).symlink_to(target)
        self.assertTrue(all(x['details'].get('sourceTrust') != 'allowlisted' for x in self.artifacts(self.scan())))

    def test_claude_configured_plugin_and_installed_cache_share_source_evidence(self):
        base = self.plugin('claude', 'claude-plugins-official')
        self.write('.claude/settings.json', {'enabledPlugins': {'example@claude-plugins-official': False}})
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'example@claude-plugins-official': [{'scope': 'user', 'installPath': str(self.home / base), 'version': '1.0.0'}]}})
        result = self.scan()
        plugins = [x for x in result['observations'] if x['kind'] == 'plugin']
        self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' for x in plugins))
        self.assertTrue(any(x['details'].get('installationState') == 'installed' for x in plugins))
        self.assertTrue(any(x['enabled'] == 'disabled' for x in plugins))
        self.assertFalse(any(x['status'] == 'skipped' for x in result['sources'] if x['location'].endswith('installed_plugins.json')))

    def test_conflicting_claude_registration_does_not_inherit_trust(self):
        self.plugin('claude', 'claude-plugins-official')
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('.claude/settings.json', {'extraKnownMarketplaces': {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'other/plugins'}}}})
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unapproved' for x in self.artifacts(self.scan())))

    def test_curated_standalone_skill_requires_exact_repository_origin_and_path(self):
        base = '.codex/skills/catalog'
        self.write(base + '/.git/HEAD', 'ref: refs/heads/main\n')
        (self.home / base / '.git/objects').mkdir()
        (self.home / base / '.git/refs').mkdir()
        self.write(base + '/.git/config', '[remote "origin"]\nurl = https://github.com/openai/skills.git\n')
        self.write(base + '/skills/.curated/example/SKILL.md', '---\nname: curated-example\n---\nFixture')
        self.write(base + '/skills/.experimental/other/SKILL.md', '---\nname: experimental-example\n---\nFixture')
        skills = {x['name']: x for x in self.scan()['observations'] if x['kind'] == 'skill'}
        self.assertEqual(skills['curated-example']['details'].get('sourceTrust'), 'allowlisted')
        self.assertNotEqual(skills['experimental-example']['details'].get('sourceTrust'), 'allowlisted')
        self.write(base + '/.git/config', '[remote "origin"]\nurl = https://github.com/other/skills.git\n')
        self.assertFalse(any(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(self.scan())))

    def test_curated_skill_does_not_accept_a_nested_incomplete_git_marker(self):
        base = '.codex/skills/catalog'
        self.write('.codex/skills/.git/HEAD', 'ref: refs/heads/main\n')
        (self.home / '.codex/skills/.git/objects').mkdir()
        (self.home / '.codex/skills/.git/refs').mkdir()
        self.write(base + '/.git/config', '[remote "origin"]\nurl = https://github.com/openai/skills.git\n')
        self.write(base + '/skills/.curated/example/SKILL.md', '---\nname: example\n---\nFixture')
        self.assertFalse(any(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(self.scan())))

    def test_unknown_ref_and_unknown_source_fields_do_not_match_allowlist(self):
        self.plugin('claude', 'official')
        for source in [
            {'source': 'github', 'repo': 'anthropics/claude-plugins-official', 'ref': 'unreviewed-branch'},
            {'source': 'github', 'repo': 'anthropics/claude-plugins-official', 'url': 'https://example.test'},
            {'source': 'git', 'url': 'https://github.com/anthropics/claude-plugins-official#main'},
            {'source': 'git', 'url': 'https://github.com:8443/anthropics/claude-plugins-official'},
            {'source': 'github', 'repo': 'https://github.com/anthropics/claude-plugins-official'},
            {'source': 'git', 'url': 'anthropics/claude-plugins-official'},
            {'source': 'git', 'url': 'https://github.com/anthropics/claude-plugins-official?'},
        ]:
            self.write('.claude/plugins/known_marketplaces.json', {'official': {'source': source}})
            self.assertTrue(all(x['details'].get('sourceTrust') == 'unapproved' for x in self.artifacts(self.scan())))

    def test_marketplace_labels_redact_known_and_learned_secrets_before_export(self):
        for index, market in enumerate(('sk-proj-' + 'A' * 32, 'private-marketplace-credential-12345')):
            self.plugin('claude', market, name='example-' + str(index))
        self.write('.claude/settings.json', {'env': {'API_KEY': 'private-marketplace-credential-12345'}})
        self.write('.claude/plugins/known_marketplaces.json', {'sk-proj-' + 'A' * 32: {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        result = self.scan()
        text = json.dumps(result)
        for secret in ('sk-proj-' + 'A' * 32, 'private-marketplace-credential-12345'):
            self.assertNotIn(secret, text)
        artifacts = self.artifacts(result)
        self.assertTrue(all('redacted' in x['details']['marketplaceId'] for x in artifacts))
        self.assertTrue(any(x['details']['sourceTrust'] == 'allowlisted' for x in artifacts), 'raw source keys must still join before redaction')
        evidence = [e['value'] for f in result['findings'] for e in f['evidence'] if 'marketplaceId' in e['value']]
        self.assertTrue(evidence)
        self.assertTrue(all('redacted' in item['marketplaceId'] for item in evidence))

    def test_marketplace_labels_remove_the_account_name_from_details_and_findings(self):
        self.home = self.home.rename(self.home.parent / 'marketplace-owner')
        self.plugin('claude', 'marketplace-owner')
        result = self.scan()
        self.assertNotIn('marketplace-owner', json.dumps(result))
        self.assertTrue(all(x['details']['marketplaceId'] == '[account]' for x in self.artifacts(result)))
        evidence = [e['value'] for f in result['findings'] for e in f['evidence'] if 'marketplaceId' in e['value']]
        self.assertTrue(evidence)
        self.assertTrue(all(item['marketplaceId'] == '[account]' for item in evidence))

    def test_redacted_marketplaces_keep_distinct_parentage(self):
        for suffix in ('A', 'B'):
            self.plugin('claude', 'sk-proj-' + suffix * 32)
        result = self.scan()
        plugins = [x for x in self.artifacts(result) if x['kind'] == 'plugin']
        skills = [x for x in self.artifacts(result) if x['kind'] == 'skill']
        self.assertEqual(len(plugins), 2)
        self.assertEqual(len(skills), 2)
        self.assertEqual({x['details']['parentId'] for x in skills}, {x['id'] for x in plugins})
        self.assertEqual({x['details']['marketplaceId'] for x in plugins}, {'[redacted]'})
        self.assertFalse(any(key.startswith('_') for x in result['observations'] for key in x))

    def test_git_default_url_does_not_establish_curated_origin(self):
        base = '.codex/skills/catalog'
        self.write(base + '/.git/HEAD', 'ref: refs/heads/main\n')
        (self.home / base / '.git/objects').mkdir()
        (self.home / base / '.git/refs').mkdir()
        self.write(base + '/.git/config', '[DEFAULT]\nurl = https://github.com/openai/skills.git\n[remote "origin"]\nfetch = +refs/heads/*:refs/remotes/origin/*\n')
        self.write(base + '/skills/.curated/example/SKILL.md', '---\nname: example\n---\nFixture')
        self.assertFalse(any(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(self.scan())))

    def test_git_url_rewrites_do_not_establish_curated_origin(self):
        base = '.codex/skills/catalog'
        self.write(base + '/.git/HEAD', 'ref: refs/heads/main\n')
        (self.home / base / '.git/objects').mkdir()
        (self.home / base / '.git/refs').mkdir()
        self.write(base + '/skills/.curated/example/SKILL.md', '---\nname: example\n---\nFixture')
        for section in ('url.evil', 'URL.evil', 'url "https://unapproved.test/"', 'url\t"https://unapproved.test/"'):
            with self.subTest(section=section):
                self.write(base + '/.git/config', '[remote "origin"]\nurl = https://github.com/openai/skills.git\n[' + section + ']\ninsteadOf = https://github.com/\n')
                self.assertFalse(any(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(self.scan())))

    def test_source_quota_preserves_remote_plugin_and_unresolved_provenance(self):
        from palma_scan.baseline import _merge
        from palma_scan.collector import _Collector
        from palma_scan.engine.collection import Collection, CollectOptions
        from palma_scan.engine.paths import Candidate
        base = '.codex/plugins/cache/openai-curated-remote/example/1.0.0'
        self.write(base + '/.codex-plugin/plugin.json', {'name': 'example', 'version': '1.0.0'})
        self.write('.codex/plugins/cache/openai-curated-remote/example/.codex-remote-plugin-install.json', {'schema_version': 1, 'remote_plugin_id': 'plugin_fixture'})
        root = self.home / '.codex/plugins/cache'
        candidate = Candidate('codex', 'user', root, '~/.codex/plugins/cache', 'directory', 'plugins')
        collection = Collection(CollectOptions(home=self.home, os_name='linux', environ={}, max_sources=8), ('fixture',), [candidate])
        collection.run()
        collector = _Collector()
        _merge(collector, collection, '~', [])
        plugins = [x for x in collector.observations if x['kind'] == 'plugin']
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0]['details']['sourceTrust'], 'unresolved')
        self.assertTrue(collector.gaps)
        self.assertTrue(any(x['status'] == 'skipped' for x in collector.sources))

    def test_local_configurations_do_not_all_receive_critical(self):
        self.write('.codex/config.toml', '[mcp_servers.local]\ncommand="node"\n[mcp_servers.remote]\nurl="https://example.test/mcp"\n')
        self.write('.codex/skills/mine/SKILL.md', '---\nname: mine\ndescription: Fixture\n---\nLocal instructions')
        findings = {x['ruleId']: x for x in self.scan()['findings']}
        self.assertEqual(findings['mcp-local-unaudited']['severity'], 'high')
        self.assertEqual(findings['mcp-network-direct']['severity'], 'high')
        self.assertEqual(findings['skills-local-unreviewed']['severity'], 'high')


if __name__ == '__main__':
    unittest.main()
