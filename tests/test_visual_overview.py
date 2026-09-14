"""Overview counts describe declarations, not inferred activity or compliance."""
import unittest

from test_inventory_groups import observation
from test_report import Document, snapshot
from palma_scan.report import render_report


class VisualOverviewTests(unittest.TestCase):
    def test_client_graph_preserves_local_remote_unknown_and_disabled_counts(self):
        from palma_scan.report_overview import inventory_graph
        records = [observation('a', 'mcp', 'tools', execution='local'),
                   observation('b', 'mcp', 'tools', execution='remote'),
                   observation('c', 'mcp', 'unknown'),
                   observation('d', 'skill', 'helper'),
                   observation('e', 'skill', 'helper', 'cursor'),
                   observation('f', 'plugin', 'plugin', 'cursor')]
        disabled = observation('g', 'mcp', 'disabled', execution='remote')
        disabled['enabled'] = 'disabled'
        records.append(disabled)
        graph = inventory_graph(records)
        self.assertEqual(graph['mcpNames'], 3)
        self.assertEqual(graph['skillNames'], 1)
        self.assertEqual(graph['plugins'], 1)
        codex = next(item for item in graph['clients'] if item['client'] == 'codex')
        self.assertEqual(codex['reach'], {'local': 1, 'remote': 1, 'unknown': 1, 'disabled': 1})
        self.assertEqual(codex['mcpNames'], 3)
        self.assertEqual(codex['mcpConfigurations'], 4)

    def test_loopback_is_local_and_gateway_is_remote_without_double_counting(self):
        from palma_scan.report_overview import inventory_graph
        graph = inventory_graph([observation('a', 'mcp', 'a', endpointScope='loopback', execution='remote'),
                                 observation('b', 'mcp', 'b', execution='remote', governedBy='palma-gateway')])
        self.assertEqual(graph['reach'], {'local': 1, 'remote': 1, 'unknown': 0, 'disabled': 0})

    def test_initial_view_has_collapsed_sections_and_individual_findings(self):
        output = render_report(snapshot(), {})
        document = Document(output)
        sections = [attrs for tag, attrs in document.tags if tag == 'details' and attrs.get('class') == 'report-disclosure']
        self.assertEqual({attrs['id'] for attrs in sections}, {'findings', 'inventory', 'coverage', 'eu-ai-regulation', 'client-map'})
        self.assertTrue(all('open' not in attrs for attrs in sections))
        cards = [attrs for tag, attrs in document.tags if tag == 'details' and attrs.get('class') == 'finding-details']
        self.assertEqual(len(cards), 2)
        self.assertTrue(all('open' not in attrs for attrs in cards))
        self.assertIn('Why it matters', output)

    def test_information_only_findings_do_not_drive_review_headline(self):
        data = snapshot()
        data['findings'] = [data['findings'][0]]
        output = render_report(data, {})
        overview = output.split('id="overview"', 1)[1].split('id="client-map"', 1)[0]
        text = ' '.join(Document(overview).text)
        self.assertIn('No priority review items', text)
        self.assertNotIn(data['findings'][0]['recommendation'], text)
        self.assertIn('1 informational', text)

    def test_overview_graph_does_not_lose_withheld_identity_groups(self):
        data = snapshot()
        data['observations'] = [observation('a', 'mcp', 'private-a.example'), observation('b', 'mcp', 'private-b.example')]
        output = render_report(data, {}, share=True)
        self.assertIn('data-mcp-names="2"', output)
        self.assertNotIn('private-a.example', output)

    def test_shared_configuration_group_is_not_counted_as_an_ai_application(self):
        data = snapshot()
        data['observations'] = [observation('a', 'client', 'Codex', 'codex'),
                                observation('b', 'client', 'Shared skills', 'shared'),
                                observation('c', 'skill', 'helper', 'shared')]
        output = render_report(data, {})
        self.assertIn('<strong>1</strong><span>AI clients</span>', output)
        self.assertIn('2 client groups', output)

    def test_local_coverage_exposes_only_safe_diagnostic_codes(self):
        data = snapshot()
        data['sources'] = [{'id': 'error', 'client': 'machine', 'status': 'error', 'location': 'machine:discovery/area-1',
                            'metadata': {'errorDiagnostics': [
                                {'stage': 'boundary-check', 'kind': 'read-gap', 'reason': 'io_error', 'windowsError': 5,
                                 'privateMessage': 'PRIVATE_EXCEPTION'},
                                {'stage': 'PRIVATE_STAGE', 'kind': 'PRIVATE_KIND', 'reason': 'PRIVATE_REASON', 'errno': True},
                                {'errno': 2 ** 64}]}}]
        local = render_report(data, {})
        self.assertIn('stage: boundary-check', local)
        self.assertIn('windowsError: 5', local)
        for value in ('PRIVATE_EXCEPTION', 'PRIVATE_STAGE', 'PRIVATE_KIND', 'PRIVATE_REASON', 'errno: True', str(2 ** 64)):
            self.assertNotIn(value, local)
        shared = render_report(data, {}, share=True)
        self.assertNotIn('stage: boundary-check', shared)
        self.assertNotIn('windowsError: 5', shared)

    def test_allowlisted_source_is_visible_without_claiming_audit(self):
        data = snapshot()
        data['observations'] = [observation('a', 'skill', 'helper', sourceTrust='allowlisted', auditStatus='not-assessed')]
        output = render_report(data, {})
        self.assertIn('Allowlisted source', output)
        self.assertNotIn('Audit passed', output)


if __name__ == '__main__':
    unittest.main()
