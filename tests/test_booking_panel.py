"""Booking stays a fixed navigation link; top callouts reflect stored priorities."""
import copy
import unittest
from unittest.mock import patch

from test_report import Document, snapshot
from palma_scan.model import booking_link
from palma_scan.report import render_report

BOOKING = 'https://calendar.app.google/qVE3L8fGgmQWv3Hx7'


class BookingPanelTests(unittest.TestCase):
    def test_default_booking_is_visible_in_both_reports_without_network_or_scan_data(self):
        data = snapshot()
        original = copy.deepcopy(data)
        for shared in (False, True):
            with self.subTest(shared=shared), patch('socket.socket', side_effect=AssertionError('offline report')):
                output = render_report(data, {}, share=shared)
                self.assertIn('class="team-teaser"', output)
                panel = output.split('class="team-teaser"', 1)[1].split('</aside>', 1)[0]
                links = [attrs for tag, attrs in Document(panel).tags if tag == 'a']
                self.assertEqual(len(links), 1)
                self.assertEqual(links[0]['href'], BOOKING)
                self.assertEqual(links[0]['rel'], 'noreferrer noopener')
                self.assertEqual(links[0]['target'], '_blank')
                self.assertIn('See the bigger picture', panel)
                self.assertIn('Illustrative team view', panel)
                self.assertIn('does not create an aggregated view or send any results', panel)
                self.assertLess(output.index('id="coverage"'), output.index('class="team-teaser"'))
                self.assertLess(output.index('class="team-teaser"'), output.index('class="local-note local-note-end"'))
                self.assertFalse(any(tag in {'iframe','form'} for tag, _ in Document(output).tags))
        self.assertEqual(data, original)

    def test_only_the_specific_google_booking_url_is_allowed(self):
        self.assertEqual(booking_link(None), BOOKING)
        self.assertEqual(booking_link(BOOKING), BOOKING)
        self.assertEqual(booking_link('https://palma.ai/team'), 'https://palma.ai/team')
        for unsafe in (BOOKING + '?email=private', BOOKING + '#private', BOOKING + '/extra',
                       'https://calendar.app.google/another-calendar',
                       BOOKING.replace('calendar.app.google', 'calendar.app.google.evil.test'),
                       BOOKING.replace('calendar.app.google', 'user:secret@calendar.app.google'),
                       BOOKING.replace('calendar.app.google', 'calendar.app.google:443'),
                       BOOKING.replace('https:', 'http:')):
            with self.subTest(url=unsafe), self.assertRaises(ValueError):
                booking_link(unsafe)

    def test_priority_callouts_precede_charts_and_keep_exact_finding_targets(self):
        data = snapshot()
        data['findings'] = [copy.deepcopy(data['findings'][1]) for _ in range(2)]
        for index, (finding, severity) in enumerate(zip(data['findings'], ('critical', 'high'))):
            finding.update(id='callout-' + severity, severity=severity, title='Finding ' + severity)
        output = render_report(data, {})
        self.assertLess(output.index('class="priority-shortlist"'), output.index('class="overview-grid"'))
        document = Document(output)
        callouts = [attrs for tag, attrs in document.tags if tag == 'a' and attrs.get('class', '').startswith('priority-item ')]
        self.assertEqual([link['class'] for link in callouts], ['priority-item priority-item-critical','priority-item priority-item-high'])
        targets = {attrs['id']: attrs['data-severity'] for tag, attrs in document.tags if tag == 'article'}
        self.assertEqual([targets[link['href'][1:]] for link in callouts], ['critical','high'])


if __name__ == '__main__':
    unittest.main()
