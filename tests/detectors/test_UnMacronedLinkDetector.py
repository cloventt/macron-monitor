import unittest

from macron_monitor import SuspiciousRev
from macron_monitor.detectors.UnMacronedLinkDetector import unmacroned_link_regex, UnMacronedLinkDetector


class test_UnMacronedLinkDetector(unittest.TestCase):
    def test_ignores_links_without_macrons(self):
        self.assertEqual(unmacroned_link_regex.findall("there is no link here"), [])
        self.assertEqual(unmacroned_link_regex.findall("there is a no macron link [[here]]"), [])
        self.assertEqual(unmacroned_link_regex.findall("there is a no macron [[link]] here"), [])
        self.assertEqual(unmacroned_link_regex.findall("[[there]] is a no macron [[link]] here"), [])
        self.assertEqual(unmacroned_link_regex.findall("there is a no macron link [[here|here]]"), [])
        self.assertEqual(unmacroned_link_regex.findall("there is a no macron [[link|link]] here"), [])
        self.assertEqual(unmacroned_link_regex.findall("[[there|there]] is a no macron [[link]] here"), [])

    def test_ignores_links_with_macrons_but_no_replacement(self):
        self.assertEqual(unmacroned_link_regex.findall("there is a link to [[Kākapō]] here"), [])
        self.assertEqual(unmacroned_link_regex.findall("there is a link to [[Whanāu]] here"), [])
        self.assertEqual(unmacroned_link_regex.findall("the [[Kākapō]] has a [[Whanāu]]"), [])

    def test_finds_links_with_macrons_replaced(self):
        self.assertEqual(unmacroned_link_regex.findall("there is a link to [[Kākapō|Kakapo]] here"), ['Kākapō'])
        self.assertEqual(unmacroned_link_regex.findall("there is a link to [[Whanāu|Whanau]] here"), ['Whanāu'])
        self.assertEqual(unmacroned_link_regex.findall("the [[Kākapō|Kakapo]] has a [[Whanāu|Whanau]]"),
                         ['Kākapō', 'Whanāu'])

    def test_detector_does_detect_not_things_that_were_deleted(self):
        detector = UnMacronedLinkDetector()

        detection_result = detector.detect({
            'title': 'Test Page',
            'user': 'Cloventt',
            'revision': {
                'old': 1234567,
                'new': 1234568,
            },
        },
        {
            'removed-context': [
                '',
                'This line has no macrons.',
                'This line has some mācrōns.',
                'This line has [[links]] inside it.',
                'This line has [[links|wikilinks]] inside it.',
                'This line links to [[parrot|Kākapō]].',
                'This line links to [[Kākapō|Kakapo]].',
            ],
            'added-contexts': [],
        })

        self.assertEqual(detection_result, None)

    def test_detector_does_detects_things_that_are_added(self):
        detector = UnMacronedLinkDetector()

        detection_result = detector.detect({
            'title': 'Test Page',
            'user': 'Cloventt',
            'revision': {
                'old': 1234567,
                'new': 1234568,
            },
        },
        {
            'removed-context': [
                '',
                'This line has no macrons.',
                'This line has some mācrōns.',
                'This line has [[links]] inside it.',
                'This line has [[links|wikilinks]] inside it.',
                'This line links to [[parrot|Kākapō]].',
                'This line links to [[Kākapō|Kakapo]].',
            ],
            'added-context': [
                '',
                'This line has no macrons.',
                'This line has some mācrōns.',
                'This line has [[links]] inside it.',
                'This line has [[links|wikilinks]] inside it.',
                'This line links to [[parrot|Kākapō]].',
                'This line links to [[Kākapō|Kakapo]].',
                'This line links to [[Whanāu|family]].',
            ],
        })

        self.assertEqual(detection_result, SuspiciousRev(
            alert_page='User:MacronMonitor/LinkAlerts',
            title='Test Page',
            user='Cloventt',
            revision={
                'old': 1234567,
                'new': 1234568,
            },
            reason="link descriptions overwrite macrons from ''Kākapō, Whanāu''"
        ))


if __name__ == '__main__':
    unittest.main()
