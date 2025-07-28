import unittest

from macron_monitor import SuspiciousRev
from macron_monitor.detectors.UnMacronedLinkDetector import link_regex, UnMacronedLinkDetector
from tests.detectors import MockWPNZArticleProvider


class test_UnMacronedLinkDetector(unittest.TestCase):
    def test_link_regex(self):
        self.assertEqual([], link_regex.findall("there is no link here"))
        self.assertEqual([], link_regex.findall("there is no piped link [[here]]"))
        self.assertEqual([], link_regex.findall("there is a macron but no piped link [[hēre]]"))
        self.assertEqual([], link_regex.findall("there is no macron but a piped link [[here|here]]"))
        self.assertEqual([('hēre', 'hēre')], link_regex.findall("there is a macron and a piped link [[hēre|hēre]]"))
        self.assertEqual([('hēre', 'here')], link_regex.findall("there is a macron and a piped link [[hēre|here]]"))
        self.assertEqual([('ĀĒĪŌŪāēīōū', 'ĀĒĪŌŪāēīōū')], link_regex.findall("there is a macron and a piped link [[ĀĒĪŌŪāēīōū|ĀĒĪŌŪāēīōū]]"))
        self.assertEqual([('ĀĒĪŌŪāēīōū', 'AEIOUaeiou')], link_regex.findall("there is a macron and a piped link [[ĀĒĪŌŪāēīōū|AEIOUaeiou]]"))

    def test_detector_does_detect_not_things_that_were_deleted(self):
        article_provider = MockWPNZArticleProvider()
        article_provider.article_titles.update(['Whanāu', 'Kākapō'])
        detector = UnMacronedLinkDetector(article_provider)

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
                'added-context': [],
            })

        self.assertEqual(detection_result, None)

    def test_detector_does_detects_things_that_are_added(self):
        article_provider = MockWPNZArticleProvider()
        article_provider.article_titles.update(['Whanāu', 'Kākapō'])
        detector = UnMacronedLinkDetector(article_provider)

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
                    'This line links to [[Whanāu|family]].',
                    'This line links to [[Whanāu|family]].',
                    'This is a Japanese link to [[Kyūshu]] in Japan.',
                ],
            })

        self.assertEqual(detection_result, SuspiciousRev(
            alert_page='User:MacronMonitor/Alerts',
            title='Test Page',
            user='Cloventt',
            revision={
                'old': 1234567,
                'new': 1234568,
            },
            reason="linkpipe over macrons in link to WPNZ article(s) '''(<nowiki>[[Kākapō|Kakapo]], [[Whanāu|family]]</nowiki>)'''"
        ))

    def test_detector_catches_partial_pipe_over_word(self):
        article_provider = MockWPNZArticleProvider()
        article_provider.article_titles.update(['Kākāpō'])
        detector = UnMacronedLinkDetector(article_provider)

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
                    'This line links to [[Kākapō]].',
                ],
                'added-context': [
                    'This line links to [[Kākāpō|Kākapo]].',
                ],
            })

        self.assertEqual(detection_result, SuspiciousRev(
            alert_page='User:MacronMonitor/Alerts',
            title='Test Page',
            user='Cloventt',
            revision={
                'old': 1234567,
                'new': 1234568,
            },
            reason="linkpipe over macrons in link to WPNZ article(s) '''(<nowiki>[[Kākāpō|Kākapo]]</nowiki>)'''"
        ))


if __name__ == '__main__':
    unittest.main()
