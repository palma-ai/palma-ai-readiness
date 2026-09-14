"""Offline provenance joins and priority calibration; all homes are synthetic."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from palma_scan.collector import collect
from palma_scan.model import validate
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
        return validate(result)

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
        base = self.plugin('claude', 'claude-plugins-official')
        result = self.scan()
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unresolved' for x in self.artifacts(result)))
        rules = {x['ruleId'] for x in result['findings']}
        # Downloaded without an installation record: cached (Info), not a verification task yet.
        self.assertNotIn('artifacts-unresolved-source', rules)
        self.assertIn('plugins-cached-only', rules)
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'example@claude-plugins-official': [{'scope': 'user', 'installPath': str(self.home / base), 'version': '1.0.0'}]}})
        result = self.scan()
        ids = {x['id'] for x in self.artifacts(result)}
        # Installed with unknown provenance is a verification task (High), not a known-unapproved source (Critical).
        [finding] = [x for x in result['findings'] if x['ruleId'] == 'artifacts-unresolved-source']
        self.assertEqual(finding['severity'], 'high')
        self.assertTrue(ids <= set(finding['observationIds']))
        self.assertIn('could not be resolved locally', finding['summary'])
        self.assertFalse(any(x['ruleId'] == 'artifacts-unapproved-marketplace' for x in result['findings']))
        self.assertFalse(any(x['ruleId'] == 'skills-local-unreviewed' for x in result['findings']))

    def test_declared_source_outside_the_allowlist_is_critical(self):
        base = self.plugin('claude', 'claude-plugins-official')
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'other/claude-plugins-official'}}})
        result = self.scan()
        rules = {x['ruleId'] for x in result['findings']}
        # Downloaded but not installed: the cached-pack finding, not an audit task yet.
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unapproved' for x in self.artifacts(result)))
        self.assertNotIn('artifacts-unapproved-marketplace', rules)
        self.assertIn('plugins-cached-only', rules)
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'example@claude-plugins-official': [{'scope': 'user', 'installPath': str(self.home / base), 'version': '1.0.0'}]}})
        result = self.scan()
        ids = {x['id'] for x in self.artifacts(result)}
        [finding] = [x for x in result['findings'] if x['ruleId'] == 'artifacts-unapproved-marketplace']
        self.assertEqual(finding['severity'], 'critical')
        self.assertTrue(ids <= set(finding['observationIds']))
        self.assertFalse(any(x['ruleId'] == 'artifacts-unresolved-source' for x in result['findings']))

    def test_codex_bundled_system_skills_are_allowlisted_only_with_their_marker(self):
        self.write('.codex/skills/.system/skill-creator/SKILL.md', '---\nname: skill-creator\n---\nBundled fixture')
        self.write('.codex/skills/mine/SKILL.md', '---\nname: mine\n---\nLocal fixture')
        result = self.scan()
        skills = {x['name']: x for x in result['observations'] if x['kind'] == 'skill'}
        self.assertNotEqual(skills['skill-creator']['details'].get('sourceTrust'), 'allowlisted', 'a .system folder alone is not evidence')
        marker = '.codex/skills/.system/.codex-system-skills.marker'
        self.write(marker, 'c0ffee1234abcdef\n')
        result = self.scan()
        skills = {x['name']: x for x in result['observations'] if x['kind'] == 'skill'}
        self.assertEqual((skills['skill-creator']['details'].get('sourceTrust'), skills['skill-creator']['details'].get('sourcePolicyId')),
                         ('allowlisted', 'openai-codex-system-skills'))
        self.assertEqual(skills['skill-creator']['details']['auditStatus'], 'not-assessed')
        self.assertIsNone(skills['mine']['details'].get('sourceTrust'))
        findings = {x['ruleId']: x for x in result['findings']}
        self.assertEqual(findings['skills-local-unreviewed']['observationIds'], [skills['mine']['id']])
        self.assertEqual(findings['skills-local-unreviewed']['title'], 'Local skills without a recorded review')
        self.assertIn(skills['skill-creator']['id'], findings['artifacts-allowlisted-source']['observationIds'])
        self.assertNotIn('c0ffee1234abcdef', json.dumps(result), 'the marker value is never exported')
        self.write(marker, '<html>not a marker</html>')
        result = self.scan()
        skills = {x['name']: x for x in result['observations'] if x['kind'] == 'skill'}
        self.assertNotEqual(skills['skill-creator']['details'].get('sourceTrust'), 'allowlisted')

    def test_a_system_skills_folder_inside_a_project_cannot_launder_a_skill(self):
        self.write('code/app/.codex/skills/.system/evil/SKILL.md', '---\nname: evil\n---\nSpoofed fixture')
        self.write('code/app/.codex/skills/.system/.codex-system-skills.marker', 'deadbeef\n')
        with patch('subprocess.Popen', side_effect=AssertionError('no process')):
            result = collect(self.home, [self.home / 'code/app'], scope_type='copied-home')
        result['findings'] = evaluate(result)
        [skill] = [x for x in result['observations'] if x['kind'] == 'skill']
        self.assertNotEqual(skill['details'].get('sourceTrust'), 'allowlisted')
        self.assertIn(skill['id'], next(x for x in result['findings'] if x['ruleId'] == 'skills-local-unreviewed')['observationIds'])

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

    def test_remote_install_record_ids_are_opaque_printable_tokens(self):
        self.plugin('codex', 'openai-curated-remote')
        metadata = '.codex/plugins/cache/openai-curated-remote/example/.codex-remote-plugin-install.json'
        for accepted in ('plugin_~abc123~DEF456', 'id/with+base64=', 'x' * 200):
            self.write(metadata, {'schema_version': 1, 'remote_plugin_id': accepted})
            result = self.scan()
            self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(result)), accepted)
            [pack] = [x for x in result['observations'] if x['kind'] == 'plugin']
            self.assertEqual(pack['details']['installationState'], 'installed')
        for rejected in ('plugin id', 'x' * 201, 'tab\tid', 'newline\n', 'caf\u00e9'):
            self.write(metadata, {'schema_version': 1, 'remote_plugin_id': rejected})
            self.assertTrue(all(x['details'].get('sourceTrust') != 'allowlisted' for x in self.artifacts(self.scan())), rejected)

    def test_codex_managed_local_marketplaces_are_allowlisted_only_at_their_managed_paths(self):
        cases = (('openai-bundled', '.codex/.tmp/bundled-marketplaces/openai-bundled'),
                 ('openai-primary-runtime', '.cache/codex-runtimes/codex-primary-runtime/plugins/openai-primary-runtime'))
        for market, relative in cases:
            self.plugin('codex', market)
        managed = ''.join(f'[marketplaces.{market}]\nsource_type="local"\nsource=\'{self.home / relative}\'\n[plugins."example@{market}"]\nenabled=true\n'
                          for market, relative in cases)
        self.write('.codex/config.toml', managed)
        result = self.scan()
        packs = [x for x in self.artifacts(result) if x['kind'] == 'plugin']
        self.assertEqual({x['details'].get('marketplaceId') for x in packs}, {market for market, _ in cases})
        self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' and x['details']['installationState'] == 'installed'
                            and x['enabled'] == 'enabled' for x in packs), [x['details'] for x in packs])
        self.assertEqual({x['details'].get('sourcePolicyId') for x in packs}, {'openai-codex-bundled-plugins', 'openai-codex-primary-runtime'})
        elsewhere = ''.join(f'[marketplaces.{market}]\nsource_type="local"\nsource=\'{self.home / "elsewhere" / market}\'\n' for market, _ in cases)
        self.write('.codex/config.toml', elsewhere)
        result = self.scan()
        self.assertTrue(all(x['details'].get('sourceTrust') == 'unapproved' for x in self.artifacts(result)), 'a reserved name at another path is not Codex-managed')
        # Codex resolves its runtime cache per platform; the managed folders below it are what count.
        self.write('.codex/config.toml', '[marketplaces.openai-primary-runtime]\nsource_type="local"\nsource="/data/xdg-cache/codex-runtimes/codex-primary-runtime/plugins/openai-primary-runtime"\n'
                   '[marketplaces.openai-bundled]\nsource_type="local"\nsource="/opt/codex-home/.tmp/bundled-marketplaces/openai-bundled"\n')
        result = self.scan()
        self.assertTrue(all(x['details'].get('sourceTrust') == 'allowlisted' for x in self.artifacts(result)), [x['details'] for x in self.artifacts(result)])

    def test_codex_config_only_pack_entries_take_their_marketplaces_provenance(self):
        managed = self.home / '.codex/.tmp/bundled-marketplaces/openai-bundled'
        self.write('.codex/config.toml', f'[marketplaces.openai-bundled]\nsource_type="local"\nsource=\'{managed}\'\n'
                   '[marketplaces.team]\nsource_type="git"\nsource="https://example.invalid/team.git"\n'
                   '[plugins."app-tools@openai-bundled"]\nenabled=true\n[plugins."helper@team"]\nenabled=true\n[plugins."loose@nowhere"]\nenabled=false\n')
        result = self.scan()
        entries = {x['name']: x['details'] for x in result['observations'] if x['kind'] == 'plugin'}
        self.assertEqual({name: d.get('sourceTrust') for name, d in entries.items()},
                         {'app-tools@openai-bundled': 'allowlisted', 'helper@team': 'unapproved', 'loose@nowhere': 'unresolved'})
        self.assertEqual(entries['app-tools@openai-bundled']['sourceEvidence'], ['marketplace-config'])
        self.assertTrue(all(d['installationState'] == 'config_only' for d in entries.values()))
        self.assertEqual({x['name']: x['enabled'] for x in result['observations'] if x['kind'] == 'plugin'}['loose@nowhere'], 'disabled')
        rules = {x['ruleId']: x['severity'] for x in result['findings']}
        self.assertEqual(rules.get('artifacts-unapproved-marketplace'), 'critical')
        self.assertEqual(rules.get('artifacts-unresolved-source'), 'high')
        self.assertNotIn('plugins-unknown-origin', rules)

    def test_project_codex_config_cannot_place_a_reserved_marketplace(self):
        self.plugin('codex', 'openai-bundled')
        self.write('.codex/config.toml', '[plugins."other@openai-bundled"]\nenabled=true\n')
        managed = self.home / 'code/app/.codex/.tmp/bundled-marketplaces/openai-bundled'
        self.write('code/app/.codex/config.toml', f'[marketplaces.openai-bundled]\nsource_type="local"\nsource=\'{managed}\'\n[plugins."tool@openai-bundled"]\nenabled=true\n')
        with patch('subprocess.Popen', side_effect=AssertionError('no process')):
            result = collect(self.home, [self.home / 'code/app'], scope_type='copied-home')
        trust = {(x['name'], x['details'].get('installationState')): x['details'].get('sourceTrust') for x in result['observations'] if x['kind'] == 'plugin'}
        # Cached content under a reserved name needs Codex's own marketplace entry; a bare switch only names Codex's catalog.
        self.assertEqual(trust, {('example', 'cached'): 'unresolved', ('other@openai-bundled', 'config_only'): 'allowlisted', ('tool@openai-bundled', 'config_only'): 'allowlisted'})
        self.assertTrue(all(x['details'].get('sourceEvidence') == ['reserved-marketplace-name'] for x in result['observations'] if x['kind'] == 'plugin' and '@' in x['name']))
        account = self.home / '.codex/.tmp/bundled-marketplaces/openai-bundled'
        self.write('.codex/config.toml', f'[marketplaces.openai-bundled]\nsource_type="local"\nsource=\'{account}\'\n[plugins."other@openai-bundled"]\nenabled=true\n')
        with patch('subprocess.Popen', side_effect=AssertionError('no process')):
            result = collect(self.home, [self.home / 'code/app'], scope_type='copied-home')
        trust = {x['name']: x['details'].get('sourceTrust') for x in result['observations'] if x['kind'] == 'plugin'}
        # The account's declaration governs the cached pack and both configured entries.
        self.assertEqual(trust, {'example': 'allowlisted', 'other@openai-bundled': 'allowlisted', 'tool@openai-bundled': 'allowlisted'})

    def test_managed_marketplace_records_from_other_hosts_and_odd_shapes_stay_unapproved(self):
        self.plugin('codex', 'openai-bundled')
        cases = (('C:\\Users\\Someone\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled', 'allowlisted'),
                 ('/Users/someone/.codex/.tmp/bundled-marketplaces/openai-bundled', 'allowlisted'),
                 ('.codex/.tmp/bundled-marketplaces/openai-bundled', 'unapproved'),
                 ('~/.codex/.tmp/bundled-marketplaces/openai-bundled', 'unapproved'),
                 (str(self.home / '.codex/.tmp/../.tmp/bundled-marketplaces/openai-bundled'), 'unapproved'),
                 (str(self.home / '.codex/.tmp/bundled-marketplaces/openai-bundled') + '\n', 'unapproved'),
                 (str(self.home / '.codex/.tmp/bundled-marketplaces/openai-bundled-alpha'), 'unapproved'),
                 ('', 'unapproved'))
        for source, expected in cases:
            escaped = source.replace('\\', '\\\\').replace('\n', '\\n')
            self.write('.codex/config.toml', f'[marketplaces.openai-bundled]\nsource_type="local"\nsource="{escaped}"\n')
            result = self.scan()
            trusts = {x['details'].get('sourceTrust') for x in self.artifacts(result)}
            self.assertEqual(trusts, {expected}, source)
        self.write('.codex/config.toml', '[marketplaces.openai-bundled]\nsource_type="local"\nsource=7\n')
        result = self.scan()
        self.assertEqual({x['details'].get('sourceTrust') for x in self.artifacts(result)}, {'unapproved'})

    def test_an_installed_packs_account_switch_is_the_pack_not_a_second_entry(self):
        self.plugin('codex', 'openai-curated-remote')
        self.write('.codex/plugins/cache/openai-curated-remote/example/.codex-remote-plugin-install.json', {'schema_version': 1, 'remote_plugin_id': 'plugin_1234567890'})
        self.write('.codex/config.toml', '[plugins."example@openai-curated-remote"]\nenabled=false\n[plugins."absent@openai-curated-remote"]\nenabled=true\n')
        base = self.plugin('claude', 'claude-plugins-official')
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'example@claude-plugins-official': [{'scope': 'user', 'installPath': str(self.home / base), 'version': '1.0.0'}]}})
        self.write('.claude/settings.json', {'enabledPlugins': {'example@claude-plugins-official': True}})
        self.write('code/app/.claude/settings.json', {'enabledPlugins': {'example@claude-plugins-official': False}})
        with patch('subprocess.Popen', side_effect=AssertionError('no process')):
            result = collect(self.home, [self.home / 'code/app'], scope_type='copied-home')
        result['findings'] = evaluate(result)
        rows = sorted((x['client'], x['name'], x['enabled'], x['details']['installationState'], x['details'].get('context')) for x in result['observations'] if x['kind'] == 'plugin')
        self.assertEqual(rows, [('claude-code', 'example', 'enabled', 'installed', 'package'),
                                ('claude-code', 'example@claude-plugins-official', 'disabled', 'config_only', 'project'),
                                ('codex', 'absent@openai-curated-remote', 'enabled', 'config_only', 'base'),
                                ('codex', 'example', 'disabled', 'installed', 'package')])
        # A switch naming Codex's reserved remote marketplace names Codex's own catalog, pack or no pack.
        [absent] = [x for x in result['observations'] if x['name'] == 'absent@openai-curated-remote']
        self.assertEqual((absent['details'].get('sourceTrust'), absent['details'].get('sourceEvidence')), ('allowlisted', ['reserved-marketplace-name']))
        # The switched-off Codex pack and the project's own switch are the disabled declarations; the account switch folded into its pack.
        [disabled] = [x for x in result['findings'] if x['ruleId'] == 'plugins-declared-disabled']
        names = {x['id']: x['name'] for x in result['observations']}
        self.assertEqual(sorted(names[i] for i in disabled['observationIds']), ['example', 'example@claude-plugins-official'])

    def test_a_switch_for_another_pack_name_is_not_folded_by_a_mismatched_manifest(self):
        base = self.plugin('claude', 'm', 'legit')
        self.write(base + '/.claude-plugin/plugin.json', {'name': 'other', 'version': '1.0.0'})
        self.write('.claude/plugins/known_marketplaces.json', {'m': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'legit@m': [{'scope': 'user', 'installPath': str(self.home / base), 'version': '1.0.0'}]}})
        self.write('.claude/settings.json', {'enabledPlugins': {'legit@m': True, 'other@m': False}})
        result = self.scan()
        rows = sorted((x['name'], x['enabled'], x['details']['installationState'], x['details'].get('sourceTrust')) for x in result['observations'] if x['kind'] == 'plugin')
        self.assertEqual(rows, [('other', 'enabled', 'installed', 'unresolved'), ('other@m', 'disabled', 'config_only', 'allowlisted')])

    def test_an_enabled_switch_keeps_a_cached_packs_connectors_in_force(self):
        base = self.plugin('claude', 'team')
        self.write(base + '/.mcp.json', {'mcpServers': {'remote': {'url': 'https://mcp.example.invalid/mcp'}}})
        self.write('.claude/plugins/known_marketplaces.json', {'team': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('.claude/settings.json', {'enabledPlugins': {'example@team': True}})
        result = self.scan()
        [pack] = [x for x in result['observations'] if x['kind'] == 'plugin']
        self.assertEqual((pack['enabled'], pack['details']['installationState']), ('enabled', 'cached'))
        # No installation record was read, but the switch is on: the pack's connector applies as written.
        [remote] = [x for x in result['findings'] if x['ruleId'] == 'mcp-network-direct']
        self.assertEqual((remote['severity'], remote['applies']), ('high', 1))
        # The missing record itself stays a hygiene note.
        self.assertEqual({x['ruleId']: x['severity'] for x in result['findings']}.get('plugins-cached-only'), 'info')

    def test_unreadable_marketplace_shapes_are_unresolved_not_unapproved(self):
        self.plugin('codex', 'openai-bundled')
        managed = self.home / '.codex/.tmp/bundled-marketplaces/openai-bundled'
        self.write('.codex/config.toml', f'[marketplaces.openai-bundled]\nsource_type="local"\nsource=\'{managed}\'\nname="OpenAI bundled"\n')
        result = self.scan()
        [pack] = [x for x in self.artifacts(result) if x['kind'] == 'plugin']
        self.assertEqual((pack['details']['sourceTrust'], pack['details']['sourceEvidence']), ('unresolved', ['unsupported-source-shape']))
        self.write('.codex/config.toml', '[marketplaces.openai-bundled]\nsource_type="git"\nsource="https://github.com/openai/plugins"\nsparse_paths=["nested"]\n')
        result = self.scan()
        [pack] = [x for x in self.artifacts(result) if x['kind'] == 'plugin']
        self.assertEqual(pack['details']['sourceTrust'], 'unapproved')

    def test_a_system_folder_outside_the_codex_home_is_not_bundled(self):
        self.write('.agents/skills/.system/evil/SKILL.md', '---\nname: evil\n---\nPlanted fixture')
        self.write('.agents/skills/.system/.codex-system-skills.marker', 'deadbeef\n')
        result = self.scan()
        copies = [x for x in result['observations'] if x['kind'] == 'skill' and x['name'] == 'evil']
        self.assertTrue(copies)
        self.assertFalse(any(x['details'].get('sourceTrust') for x in copies), [x['details'] for x in copies])

    def test_a_cached_packs_account_switch_folds_into_the_pack_too(self):
        self.plugin('claude', 'claude-plugins-official')
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('.claude/settings.json', {'enabledPlugins': {'example@claude-plugins-official': False}})
        result = self.scan()
        [pack] = [x for x in result['observations'] if x['kind'] == 'plugin']
        self.assertEqual((pack['name'], pack['enabled'], pack['details']['installationState']), ('example', 'disabled', 'cached'))
        [disabled] = [x for x in result['findings'] if x['ruleId'] == 'plugins-declared-disabled']
        self.assertEqual(disabled['observationIds'], [pack['id']])

    def test_system_skills_read_through_another_client_keep_their_bundled_provenance(self):
        self.write('.codex/skills/.system/skill-creator/SKILL.md', '---\nname: skill-creator\n---\nBundled fixture')
        self.write('.codex/skills/.system/.codex-system-skills.marker', 'c0ffee1234abcdef\n')
        result = self.scan()
        copies = [x for x in result['observations'] if x['kind'] == 'skill' and x['name'] == 'skill-creator']
        # A machine scan also lists the copy Cursor reads from the same folder; the rule keys on the
        # folder being the account's Codex home, not on the reading client.
        self.assertIn('codex', {x['client'] for x in copies})
        self.assertTrue(all(x['details'].get('sourcePolicyId') == 'openai-codex-system-skills' for x in copies),
                        {x['client']: x['details'].get('sourceTrust') for x in copies})

    def test_project_settings_use_the_accounts_marketplace_registry(self):
        self.write('.claude/plugins/known_marketplaces.json', {'claude-plugins-official': {'source': {'source': 'github', 'repo': 'anthropics/claude-plugins-official'}}})
        self.write('code/app/.claude/settings.json', {'enabledPlugins': {'example@claude-plugins-official': True}})
        with patch('subprocess.Popen', side_effect=AssertionError('no process')):
            result = collect(self.home, [self.home / 'code/app'], scope_type='copied-home')
        [pack] = [x for x in result['observations'] if x['kind'] == 'plugin']
        self.assertEqual((pack['details'].get('sourceTrust'), pack['details'].get('sourcePolicyId')), ('allowlisted', 'anthropic-official-plugins'))

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
