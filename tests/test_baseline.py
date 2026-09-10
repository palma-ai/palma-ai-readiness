"""Synthetic regression fixtures for the retained original collection engine."""
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from palma_scan.collector import collect, collect_scopes
from palma_scan.model import validate
from palma_scan.rules import evaluate


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve() / 'home'
        self.home.mkdir()

    def write(self, relative, value):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def scan(self):
        before = {str(path) for path in self.home.rglob('*')}
        with patch('subprocess.Popen', side_effect=AssertionError('must not execute')), patch('socket.socket', side_effect=AssertionError('must not connect')):
            result = collect(self.home, scope_type='copied-home')
        self.assertEqual(before, {str(path) for path in self.home.rglob('*')})
        result['findings'] = evaluate(result)
        validate(result)
        self.assertNotIn(str(self.home), json.dumps(result))
        return result

    def kinds(self, snapshot, kind):
        return [item for item in snapshot['observations'] if item['kind'] == kind]

    def test_named_profiles_are_preserved_without_claiming_they_are_selected(self):
        self.write('.codex/config.toml', 'sandbox_mode="read-only"')
        self.write('.codex/work.config.toml', 'sandbox_mode="danger-full-access"\napproval_policy="never"\n[mcp_servers.docs]\ncommand="node"')
        result = self.scan()
        profiles = [item for item in result['observations'] if item['details']['context'] == 'profile']
        self.assertTrue(profiles)
        self.assertTrue(all(item['location'] == '~/.codex/work.config.toml' for item in profiles))
        self.assertTrue(all(item['details'].get('applicability') for item in profiles if item['kind'] != 'client'))

    def test_named_profiles_preserve_explicit_disabled_connectors_and_plugins(self):
        self.write('.codex/work.config.toml', '[mcp_servers.disabled]\ncommand="node"\nenabled=false\n[mcp_servers.configured]\ncommand="node"\nenabled=true\n[mcp_servers.unspecified]\ncommand="node"\n')
        self.write('Library/Application Support/Code/User/profiles/work/settings.json', {
            'chat.plugins.enabledPlugins': {'disabled-plugin': False, 'configured-plugin': True}})
        result = self.scan()
        for kind, disabled, configured in [('mcp', 'disabled', 'configured'), ('plugin', 'disabled-plugin', 'configured-plugin')]:
            items = {item['name']: item for item in self.kinds(result, kind)}
            self.assertEqual(items[disabled]['enabled'], 'disabled')
            self.assertEqual(items[configured]['enabled'], 'enabled')
            self.assertTrue(all(item['details']['context'] == 'profile' for item in items.values()))
            self.assertTrue(all(item['details'].get('applicability') for item in items.values()))
        self.assertEqual(next(item for item in self.kinds(result, 'mcp') if item['name'] == 'unspecified')['enabled'], 'unknown')

    def test_hook_configuration_contributes_one_declaration_with_typed_evidence(self):
        self.write('.claude/settings.json', {'hooks': {'PreToolUse': [
            {'hooks': [{'type': 'command', 'command': 'PRIVATE_COMMAND'}]}]}})
        result = self.scan()
        hooks = self.kinds(result, 'hook')
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]['details']['typeCounts']['command'], 1)
        self.assertFalse(any(item['details'].get('key') == 'hooks' for item in self.kinds(result, 'setting')))
        finding = next(item for item in result['findings'] if item['ruleId'] == 'hooks-declared')
        self.assertEqual(finding['declarations'], 1)
        self.assertEqual(finding['observationIds'], [hooks[0]['id']])

    def test_hook_inventory_is_retained_when_no_typed_hook_was_extracted(self):
        self.write('.claude/settings.json', {'hooks': {'SessionStart': [{'unknown': 'PRIVATE_BODY'}]}})
        result = self.scan()
        self.assertFalse(self.kinds(result, 'hook'))
        setting = next(item for item in self.kinds(result, 'setting') if item['details'].get('key') == 'hooks')
        self.assertEqual(setting['details']['interpretation'], 'inventory-only')
        self.assertFalse(setting['details']['valueCollected'])
        source = next(item for item in result['sources'] if item['id'] == setting['sourceId'])
        self.assertEqual(source['status'], 'skipped')
        self.assertIn('a declared hook block had no interpretable handler entries', source['reasons'])
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(any(item['ruleId'] == 'hooks-declared' for item in result['findings']))
        self.assertNotIn('PRIVATE_BODY', json.dumps(result))

    def test_empty_hook_object_does_not_create_a_collection_failure(self):
        self.write('.claude/settings.json', {'hooks': {}})
        result = self.scan()
        source = next(item for item in result['sources'] if item['location'] == '~/.claude/settings.json')
        self.assertEqual(source['status'], 'collected')
        self.assertFalse(self.kinds(result, 'hook'))

    def test_rejected_environment_override_has_an_actionable_source_without_its_value(self):
        with patch.dict(os.environ, {'CODEX_HOME': '/PRIVATE_OUTSIDE_ACCOUNT'}, clear=True), \
                patch('palma_scan.baseline._known_candidates', return_value=[]), \
                patch('palma_scan.baseline.user_candidates', return_value=[]), \
                patch('palma_scan.baseline.supplemental_candidates', return_value=[]), \
                patch('palma_scan.baseline.installed_client_candidates', return_value=[]), \
                patch('palma_scan.baseline.installation_candidates', return_value=[]), \
                patch('palma_scan.baseline._add_editor_state'), \
                patch('subprocess.Popen', side_effect=AssertionError('must not execute')):
            result = collect_scopes([{'root': self.home, 'alias': '~'}], include_installations=True)
        self.assertEqual(result['status'], 'partial')
        source = next(item for item in result['sources'] if 'environment override CODEX_HOME' in item['location'])
        self.assertEqual(source['status'], 'skipped')
        self.assertIn('unsupported environment directory override', source['reason'])
        self.assertEqual(source['reasons'], [source['reason']])
        self.assertNotIn('PRIVATE_OUTSIDE_ACCOUNT', json.dumps(result))

    def test_editor_profiles_keep_separate_sources_and_native_keys(self):
        for name, enabled in [('PRIVATE_PERSON_A', True), ('PRIVATE_PERSON_B', False)]:
            self.write(f'Library/Application Support/Code/User/profiles/{name}/settings.json', {'chat.tools.global.autoApprove': enabled})
            self.write(f'Library/Application Support/Code/User/profiles/{name}/mcp.json', {'servers': {'PRIVATE_SERVER': {'command': 'node'}}})
        result = self.scan()
        settings = self.kinds(result, 'setting')
        self.assertEqual(len(settings), 2)
        self.assertEqual(len({item['sourceId'] for item in settings}), 2)
        self.assertEqual(len(self.kinds(result, 'mcp')), 2)
        self.assertEqual({item['location'] for item in settings}, {'~/Library/Application Support/Code/User/profiles/' + name + '/settings.json' for name in ('PRIVATE_PERSON_A', 'PRIVATE_PERSON_B')})

    def test_package_named_docs_is_not_skipped_and_parent_edges_resolve(self):
        base = '.codex/plugins/cache/market/docs/1.0'
        self.write(base + '/.codex-plugin/plugin.json', {'name': 'PRIVATE_PACKAGE', 'mcpServers': './tools.json'})
        self.write(base + '/tools.json', {'mcp_servers': {'PRIVATE_MCP': {'command': 'node'}}})
        self.write(base + '/skills/helper/SKILL.md', '---\nname: PRIVATE_SKILL\n---\nPRIVATE_BODY')
        self.write(base + '/agents/reviewer.md', '---\nname: PRIVATE_AGENT\ntools: Read, Bash\n---\nPRIVATE_BODY')
        self.write(base + '/hooks/hooks.json', {'hooks': {'PreToolUse': [{'hooks': [{'type': 'command', 'command': 'PRIVATE_COMMAND'}]}]}})
        result = self.scan()
        plugin = self.kinds(result, 'plugin')[0]
        self.assertEqual(plugin['details']['activation'], 'cached')
        for kind in ('mcp', 'skill', 'agent', 'hook'):
            self.assertEqual(len(self.kinds(result, kind)), 1)
            self.assertEqual(self.kinds(result, kind)[0]['details']['parentId'], plugin['id'])
        self.assertEqual(plugin['name'], 'PRIVATE_PACKAGE')
        for body in ('PRIVATE_BODY', 'PRIVATE_COMMAND'):
            self.assertNotIn(body, json.dumps(result))

    def test_custom_claude_components_are_parsed_but_sibling_assets_are_not(self):
        base = '.claude/plugins/cache/vendor/custom/1.0'
        self.write(base + '/.claude-plugin/plugin.json', {'name': 'custom', 'skills': './extra-skills', 'agents': './selected/agent.md'})
        self.write(base + '/skills/default/SKILL.md', '---\nname: default\n---\nbody')
        self.write(base + '/extra-skills/extra/SKILL.md', '---\nname: extra\n---\nbody')
        self.write(base + '/selected/agent.md', '---\nname: selected\n---\nbody')
        self.write(base + '/selected/ignored.md', '---\nname: ignored\n---\nbody')
        result = self.scan()
        self.assertEqual(len(self.kinds(result, 'skill')), 2)
        self.assertEqual(len(self.kinds(result, 'agent')), 1)

    def test_bundle_digest_changes_when_bundled_script_changes_without_exporting_it(self):
        self.write('.agents/skills/demo/SKILL.md', '---\nname: PRIVATE_SKILL\n---\nPRIVATE_INSTRUCTIONS')
        script = self.write('.agents/skills/demo/scripts/run.py', 'PRIVATE_FIRST_SCRIPT')
        first = self.scan()
        script.write_text('PRIVATE_SECOND_SCRIPT')
        second = self.scan()
        one, two = self.kinds(first, 'skill')[0], self.kinds(second, 'skill')[0]
        self.assertEqual(one['id'], two['id'])
        self.assertNotEqual(one['details']['digest'], two['details']['digest'])
        self.assertEqual(one['details']['filesHashed'], 2)
        self.assertEqual(two['name'], 'PRIVATE_SKILL')
        for body in ('PRIVATE_INSTRUCTIONS', 'PRIVATE_FIRST_SCRIPT', 'PRIVATE_SECOND_SCRIPT'):
            self.assertNotIn(body, json.dumps(second))

    def test_claude_state_switches_are_inventory_not_current_permission_grants(self):
        self.write('.claude.json', {'claudeInChromeEnabled': True, 'bypassPermissionsModeAccepted': True, 'computerUseMcpState': 'enabled', 'oauthAccount': {'emailAddress': 'PRIVATE_EMAIL'}, 'firstStartTime': 'PRIVATE_TIME'})
        result = self.scan()
        keys = {item['details']['key'] for item in self.kinds(result, 'setting')}
        self.assertTrue({'claudeInChromeEnabled', 'bypassPermissionsModeAccepted', 'computerUseMcpState'}.issubset(keys))
        self.assertFalse(any(item['severity'] == 'high' for item in result['findings']))
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_windows_virtualized_claude_config_is_kept_as_a_distinct_source(self):
        self.write('AppData/Roaming/Claude/claude_desktop_config.json', {'mcpServers': {'legacy': {'command': 'node'}}})
        self.write('AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude_desktop_config.json', {'mcpServers': {'new': {'command': 'node'}}})
        result = self.scan()
        self.assertEqual(len(self.kinds(result, 'mcp')), 2)
        self.assertEqual(len({item['sourceId'] for item in self.kinds(result, 'mcp')}), 2)

    @unittest.skipIf(os.name == 'nt', 'POSIX fixture modes')
    def test_native_versions_require_payload_but_never_execute_or_read_binary_contents(self):
        for version in ('2.1.1', '2.1.2'):
            path = self.write('.local/share/claude/versions/' + version, 'PRIVATE_BINARY' * 200000)
            path.chmod(0o755)
        result = self.scan()
        clients = [item for item in self.kinds(result, 'client') if item['details']['activation'] == 'installed']
        self.assertEqual({item['details'].get('version') for item in clients}, {'2.1.1', '2.1.2'})
        self.assertNotIn('PRIVATE_BINARY', json.dumps(result))

    @unittest.skipIf(os.name == 'nt', 'POSIX fixture modes')
    def test_renamed_macos_app_uses_verified_bundle_identity_and_payload(self):
        base = self.home / 'Applications/PRIVATE_RENAMED.app/Contents'
        base.mkdir(parents=True)
        (base / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.openai.codex', 'CFBundleShortVersionString': '26.901.1', 'CFBundleExecutable': 'Main'}))
        (base / 'MacOS').mkdir()
        (base / 'MacOS/Main').write_bytes(b'PRIVATE_BINARY')
        (base / 'MacOS/Main').chmod(0o755)
        result = self.scan()
        clients = [item for item in self.kinds(result, 'client') if item['details']['activation'] == 'installed']
        self.assertEqual([(item['client'], item['details'].get('version')) for item in clients], [('codex', '26.901.1')])
        self.assertTrue(any('PRIVATE_RENAMED.app/Contents' in item['location'] for item in clients))
        self.assertNotIn('PRIVATE_BINARY', json.dumps(result))

    def test_yaml_safe_loader_rejects_duplicate_keys_and_aliases(self):
        self.write('.continue/config.yaml', 'name: first\nname: second\n')
        self.write('.aider.conf.yml', 'first: &ref true\nyes-always: *ref\n')
        result = self.scan()
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len([source for source in result['sources'] if source['status'] == 'error']), 2)
        self.assertFalse(any(item['severity'] == 'high' for item in result['findings']))

    def test_registry_json_in_memory_gets_managed_context_without_a_raw_file(self):
        data = {'permissions': {'defaultMode': 'bypassPermissions', 'disableBypassPermissionsMode': 'disable'}}
        result = collect_scopes([], system_sources=[{'data': data, 'client': 'claude-code', 'location': 'system:HKLM/Software/Policies/ClaudeCode/Settings', 'context': 'managed'}])
        result['findings'] = evaluate(result)
        validate(result)
        self.assertFalse(any(item['severity'] == 'high' for item in result['findings']))
        self.assertTrue(all(item['details']['accountAlias'] == 'system' for item in self.kinds(result, 'setting')))

    def test_independent_accounts_are_not_reported_as_conflicting_settings(self):
        self.write('.claude/settings.json', {'permissions': {'defaultMode': 'default'}})
        other = self.home.parent / 'OTHER_PRIVATE_ACCOUNT'
        (other / '.claude').mkdir(parents=True)
        (other / '.claude/settings.json').write_text(json.dumps({'permissions': {'defaultMode': 'bypassPermissions'}}))
        result = collect_scopes([{'root': self.home, 'alias': '~'}, {'root': other, 'alias': 'user-1'}])
        self.assertNotIn('PALMA-HYGIENE-003', {item['ruleId'] for item in evaluate(result)})


if __name__ == '__main__':
    unittest.main()
