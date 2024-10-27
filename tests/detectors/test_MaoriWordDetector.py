import unittest

from macron_monitor import SuspiciousRev
from macron_monitor.detectors.MaoriWordDetector import MaoriWordDetector


class test_MaoriWordDetector(unittest.TestCase):
    def test_ignores_hunks_without_macrons(self):
        detector = MaoriWordDetector()

        result = detector.detect({
            'title': 'Test Page',
            'user': 'Cloventt',
            'revision': {
                'old': 1234567,
                'new': 1234568,
            },
        },
            {
                'removed-context': [],
                'added-context': [
                    '',
                    'This line has no macrons.',
                    'This line has some mācrōns.',
                    'This line has [[links]] inside it.',
                    'This line has [[links|wikilinks]] inside it.',
                    'This line has [[multiple]] [[links|wikilinks]] inside it.',
                ],
            })
        self.assertEqual(None, result)

    def test_ignores_correctly_spelled_words(self):
        detector = MaoriWordDetector()

        result = detector.detect({
            'title': 'Test Page',
            'user': 'Cloventt',
            'revision': {
                'old': 1234567,
                'new': 1234568,
            },
        },
            {
                'removed-context': [],
                'added-context': [
                    '',
                    'This line has [[whānau]] in it.',
                    'This line has tūī in it.',
                    'This line has tūī from Ōtautahi in it.',
                ],
            })
        self.assertEqual(None, result)

    def test_detects_misspelled_words(self):
        detector = MaoriWordDetector()

        result = detector.detect({
            'title': 'Test Page',
            'user': 'Cloventt',
            'revision': {
                'old': 1234567,
                'new': 1234568,
            },
        },
            {
                'removed-context': [],
                'added-context': [
                    '',
                    'This line has [[whanau]] in it.',
                    'This line has morena in it.',
                    'This line has tui from Otautahi in it.',
                    'This line has a "Wahine" from \'Mangere\' in it.',
                ],
            })
        self.assertEqual(SuspiciousRev(
            alert_page='User:MacronMonitor/Alerts',
            title='Test Page',
            user='Cloventt',
            revision={
                'old': 1234567,
                'new': 1234568,
            },
            reason="possible Māori word(s) missing macrons: '''mangere, morena, otautahi, tui, wahine, whanau'''"
        ), result)

    def test_ignores_misspelled_words_inside_templates(self):
        detector = MaoriWordDetector()

        result = detector.detect({
            'title': 'Test Page',
            'user': 'Cloventt',
            'revision': {
                'old': 1234567,
                'new': 1234568,
            },
        },
            {
                'removed-context': [],
                'added-context': [
                    'citation.<ref>{{citation|url=http://rnz.co.nz/te-ao-maori-is-a-word|place=Otautahi}}</ref>',
                ],
            })
        self.assertEqual(None, result)


if __name__ == '__main__':
    unittest.main()
