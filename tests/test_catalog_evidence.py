"""The retained Palma catalog receives complete sanitized observation facts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from palma_scan.collector import collect


class CatalogEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()

    def write(self, relative, value):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def scan(self):
        return collect(self.home, scope_type='copied-home')

    def items(self, snapshot, kind):
        return [item for item in snapshot['observations'] if item['kind'] == kind]

    def test_client_installation_and_auth_fields_remain_available(self):
        self.write('.claude/settings.json', {'env': {'ANTHROPIC_API_KEY': 'PRIVATE_SECRET'}})
        result = self.scan()
        client = self.items(result, 'client')[0]['details']
        self.assertEqual(client['installationState'], 'config_only')
        self.assertEqual(client['authModes'], ['api_key'])
        self.assertNotIn('PRIVATE_SECRET', json.dumps(result))

    def test_original_capability_patterns_cover_names_packages_executables_and_origins(self):
        self.write('.cursor/mcp.json', {'mcpServers': {
            'a_PRIVATE_cua_connector': {'command': 'node'},
            'b_PRIVATE': {'command': 'uvx', 'args': ['windows-mcp']},
            'c_PRIVATE': {'command': '/PRIVATE_PATH/peekaboo'},
            'd_PRIVATE': {'url': 'https://PRIVATE_USER:PRIVATE_SECRET@browserbase.private.test/PRIVATE_PATH'},
            'e_parcua_PRIVATE': {'command': 'node'},
        }})
        result = self.scan()
        entries = self.items(result, 'mcp')
        self.assertEqual([item['details']['capability'] for item in entries], ['computer', 'computer', 'computer', 'browser', None])
        self.assertEqual([item['details']['capabilityEvidence'] for item in entries[:4]], ['declaration-name', 'declared-package', 'declared-executable', 'declared-endpoint-origin'])
        self.assertTrue(all(item['details']['provider'] == 'unknown' for item in entries))
        self.assertEqual(entries[0]['details']['toolFamily'], 'computer')
        self.assertEqual(entries[0]['name'], 'a_PRIVATE_cua_connector')
        for value in ('PRIVATE_PATH', 'PRIVATE_USER', 'PRIVATE_SECRET', 'browserbase.private.test', '/peekaboo', 'windows-mcp'):
            self.assertNotIn(value, json.dumps(result))

    def test_mcp_auth_literals_and_original_transport_classes_are_preserved(self):
        self.write('.cursor/mcp.json', {'mcpServers': {
            'a': {'type': 'sdk'},
            'b': {'type': 'websocket', 'url': 'wss://private.test/mcp', 'headers': {'Authorization': 'Bearer PRIVATE_SECRET'}},
            'c': {'command': 'node', 'env': {'API_TOKEN': '${env:API_TOKEN}'}},
        }})
        result = self.scan()
        entries = self.items(result, 'mcp')
        self.assertEqual([item['details']['transport'] for item in entries], ['sdk', 'websocket', 'stdio'])
        self.assertEqual(entries[0]['details']['execution'], 'local')
        self.assertEqual(entries[1]['details']['auth'], 'bearer_header')
        self.assertTrue(entries[1]['details']['inlineCredentialPresent'])
        self.assertEqual(entries[2]['details']['auth'], 'environment_reference')
        self.assertFalse(entries[2]['details']['inlineCredentialPresent'])
        self.assertNotIn('PRIVATE_SECRET', json.dumps(result))

    def test_skills_plugins_and_agents_keep_original_catalog_facts(self):
        self.write('.agents/skills/local/SKILL.md', '---\nname: PRIVATE_SKILL\n---\nPRIVATE_BODY')
        root = '.claude/plugins/cache/vendor/PRIVATE_PACK/1.0'
        self.write(root + '/.claude-plugin/plugin.json', {'name': 'PRIVATE_PACK', 'version': '1.2.3'})
        self.write('.claude/agents/reviewer.md', '---\nname: PRIVATE_AGENT\ntools: [Read, Write, Edit, Glob, Grep, Bash, Task, Tool8, Tool9, Tool10]\n---\nPRIVATE_BODY')
        result = self.scan()
        skill = self.items(result, 'skill')[0]['details']
        plugin = self.items(result, 'plugin')[0]['details']
        agent = self.items(result, 'agent')[0]['details']
        self.assertEqual(skill['origin'], 'user')
        self.assertEqual(len(skill['digest']), 64)
        self.assertEqual(plugin['origin'], 'unknown')
        self.assertEqual(plugin['installationState'], 'cached')
        self.assertEqual(plugin['artifactType'], 'plugin')
        self.assertEqual(agent['toolCount'], 10)
        self.assertNotIn('PRIVATE_BODY', json.dumps(result))
        self.assertEqual({item['name'] for kind in ('skill', 'plugin', 'agent') for item in self.items(result, kind)}, {'PRIVATE_SKILL', 'PRIVATE_PACK', 'PRIVATE_AGENT'})

    def test_settings_keep_category_native_key_value_collection_and_staleness(self):
        self.write('.codex/config.toml', 'approval_policy="never"\n[features]\ncomputer_use=true\n')
        self.write('.claude.json', {'projects': {str(self.home / 'gone'): {'hasTrustDialogAccepted': True}}})
        result = self.scan()
        settings = self.items(result, 'setting')
        approval = next(item['details'] for item in settings if item['details']['key'] == 'approval_policy')
        self.assertEqual((approval['nativeKey'], approval['category'], approval['valueCollected'], approval['effectiveState']), ('approval_policy', 'permissions', True, 'unknown'))
        self.assertTrue(any(item['details']['effectiveState'] == 'stale' for item in settings))
        historical = next(item['details'] for item in settings if item['details']['key'] == 'projects.hasTrustDialogAccepted')
        self.assertEqual(historical['interpretation'], 'inventory-only')
        self.assertEqual(historical['category'], 'permissions')

    def test_cached_plugin_size_gap_has_actual_size_and_fixed_component_classification(self):
        root = '.codex/plugins/cache/vendor/PRIVATE_PACK/1.0'
        self.write(root + '/.codex-plugin/plugin.json', {'name': 'PRIVATE_PACK'})
        path = self.write(root + '/skills/PRIVATE_SKILL/SKILL.md', 'x' * (2 * 1024 * 1024 + 1))
        result = self.scan()
        source = next(item for item in result['sources'] if item['reason'] == 'size_limit')
        self.assertEqual(source['artifactRole'], 'skill')
        self.assertEqual(source['componentKind'], 'skill')
        self.assertEqual(source['packageState'], 'cached')
        self.assertEqual(source['sizeBytes'], path.stat().st_size)
        self.assertEqual(source['limitBytes'], 2 * 1024 * 1024)
        self.assertEqual(source['location'], '~/' + root + '/skills/PRIVATE_SKILL/SKILL.md')

    def test_cached_mcp_shape_gaps_are_classified_without_exporting_values(self):
        root = '.codex/plugins/cache/vendor/PRIVATE_PACK/1.0'
        self.write(root + '/.codex-plugin/plugin.json', {'name': 'PRIVATE_PACK'})
        self.write(root + '/.mcp.json', {'mcpServers': ['PRIVATE_MALFORMED_VALUE']})
        result = self.scan()
        sources = [item for item in result['sources'] if item.get('issueKind') == 'unsupported-mcp-shape']
        self.assertTrue(sources)
        self.assertTrue(all(item['classification'] == 'mcp-configuration' and item['packageState'] == 'cached' for item in sources))
        self.assertNotIn('PRIVATE_MALFORMED_VALUE', json.dumps(result))

    def test_local_report_retains_real_names_and_actionable_manifest_paths(self):
        self.write('.agents/skills/price-review/SKILL.md', '---\nname: Pricing review\n---\nPRIVATE_BODY')
        self.write('.claude/agents/api-review.md', '---\nname: API reviewer\n---\nPRIVATE_BODY')
        root = '.claude/plugins/cache/vendor/team-toolkit/1.0'
        self.write(root + '/.claude-plugin/plugin.json', {'name': 'Team toolkit'})
        self.write('.cursor/mcp.json', {'mcpServers': {'Internal CRM': {'command': 'PRIVATE_COMMAND', 'env': {'API_TOKEN': 'PRIVATE_SECRET'}}}})
        self.write('.claude/settings.json', {'enabledPlugins': {'reviewer@team': True}, 'hooks': {'PreToolUse': [{'hooks': [{'type': 'command', 'command': 'PRIVATE_COMMAND'}]}]}})
        result = self.scan()
        self.assertEqual(self.items(result, 'skill')[0]['name'], 'Pricing review')
        self.assertEqual(self.items(result, 'skill')[0]['location'], '~/.agents/skills/price-review/SKILL.md')
        self.assertEqual(self.items(result, 'agent')[0]['name'], 'API reviewer')
        self.assertEqual({item['name'] for item in self.items(result, 'plugin')}, {'Team toolkit', 'reviewer@team'})
        self.assertEqual(self.items(result, 'mcp')[0]['name'], 'Internal CRM')
        self.assertEqual(self.items(result, 'mcp')[0]['details']['declaration'], 'mcpServers["Internal CRM"]')
        self.assertIn('PreToolUse', self.items(result, 'hook')[0]['name'])
        self.assertFalse(any('/item-' in item['location'] for item in result['sources']))
        for private in ('PRIVATE_BODY', 'PRIVATE_COMMAND', 'PRIVATE_SECRET', str(self.home)):
            self.assertNotIn(private, json.dumps(result))

    def test_display_names_scrub_credential_values_and_url_components(self):
        self.write('.cursor/mcp.json', {'mcpServers': {
            'CRM PRIVATE_SECRET': {'command': 'node', 'env': {'API_TOKEN': 'PRIVATE_SECRET'}},
            'https://u:short@private.test/path?token=short#fragment': {'command': 'node'},
        }})
        result = self.scan()
        self.assertEqual([item['name'] for item in self.items(result, 'mcp')], ['CRM [redacted]', 'https://private.test'])
        for private in ('PRIVATE_SECRET', 'short', '?token=', '#fragment'):
            self.assertNotIn(private, json.dumps(result))

    def test_display_names_and_paths_do_not_reveal_literal_fallback_credentials(self):
        self.write('.cursor/mcp.json', {'mcpServers': {
            'CRM PRIVATE_FALLBACK_CANARY': {'command': 'node', 'env': {'API_TOKEN': '${API_TOKEN:-PRIVATE_FALLBACK_CANARY}'}}
        }})
        self.write('.agents/skills/PRIVATE_FALLBACK_CANARY/SKILL.md', '---\nname: PRIVATE_FALLBACK_CANARY review\n---\nbody')
        result = self.scan()
        self.assertNotIn('PRIVATE_FALLBACK_CANARY', json.dumps(result))
        self.assertEqual(self.items(result, 'mcp')[0]['name'], 'CRM [redacted]')

    def test_additional_client_names_and_duplicate_continue_entries_are_actionable(self):
        self.write('.config/opencode/opencode.json', {'agent': {'API reviewer': {'prompt': 'PRIVATE_BODY'}}, 'plugin': ['@team/review-plugin']})
        self.write('.openclaw/openclaw.json', {'plugins': {'entries': {'Team calendar': {'enabled': True}}}})
        self.write('.continue/config.yaml', 'mcpServers:\n - name: Pricing tools\n   command: node\n - name: Pricing tools\n   command: node\n')
        result = self.scan()
        self.assertIn('API reviewer', {item['name'] for item in self.items(result, 'agent')})
        self.assertTrue({'@team/review-plugin', 'Team calendar'} <= {item['name'] for item in self.items(result, 'plugin')})
        connections = [item for item in self.items(result, 'mcp') if item['client'] == 'continue']
        self.assertEqual([item['name'] for item in connections], ['Pricing tools', 'Pricing tools'])
        self.assertEqual({item['details']['declaration'] for item in connections}, {'mcpServers[0]', 'mcpServers[1]'})
        self.assertEqual(len({item['id'] for item in connections}), 2)
        self.assertFalse(any(source.get('issueKind') == 'unsupported-mcp-shape' for source in result['sources']))
        self.assertNotIn('PRIVATE_BODY', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
