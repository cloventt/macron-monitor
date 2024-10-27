import unittest

from macron_monitor import SuspiciousRev
from macron_monitor.detectors.UnMacronedLinkDetector import unmacroned_link_regex, UnMacronedLinkDetector
from tests.detectors import MockWPNZArticleProvider


class test_UnMacronedLinkDetector(unittest.TestCase):
    def test_ignores_links_without_macrons(self):
        self.assertEqual([], unmacroned_link_regex.findall("there is no link here"))
        self.assertEqual([], unmacroned_link_regex.findall("there is a no macron link [[here]]"))
        self.assertEqual([], unmacroned_link_regex.findall("there is a no macron [[link]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("[[there]] is a no macron [[link]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("there is a no macron link [[here|here]]"))
        self.assertEqual([], unmacroned_link_regex.findall("there is a no macron [[link|link]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("[[there|there]] is a no macron [[link]] here"))

    def test_ignores_links_with_macrons_but_no_replacement(self):
        self.assertEqual([], unmacroned_link_regex.findall("there is a link to [[Kākapō]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("there is a link to [[Whanāu]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("the [[Kākapō]] has a [[Whanāu]]"))
        self.assertEqual(
            [],
            unmacroned_link_regex.findall("[[Āorangi]] is a cool place.<ref>{{cite|url=}}</ref> [[yep]]"),
        )

    def test_finds_links_with_macrons_replaced(self):
        self.assertEqual(['Kākapō'], unmacroned_link_regex.findall("there is a link to [[Kākapō|Kakapo]] here"))
        self.assertEqual(['Whanāu'], unmacroned_link_regex.findall("there is a link to [[Whanāu|Whanau]] here"))
        self.assertEqual(
            ['Kākapō', 'Whanāu'],
            unmacroned_link_regex.findall("the [[Kākapō|Kakapo]] has a [[Whanāu|Whanau]]"),
        )
        self.assertEqual(
            ['Whanāu'],
            unmacroned_link_regex.findall("the [[Kākapō]] has a [[Whanāu|Whanau]]"),
        )

        self.assertEqual(
            ['Whanāu'],
            unmacroned_link_regex.findall("the [[Kākapō]] has ō a [[Whanāu|Whanau]]"),
        )
        self.assertEqual(
            ['Whanāu', 'Āorangi'],
            unmacroned_link_regex.findall("the [[Kākapō]] has ō a [[Whanāu|Whanau]] in [[Āorangi|Aorangi]]"),
        )

    def test_ignores_links_with_macrons_not_replaced(self):
        self.assertEqual([], unmacroned_link_regex.findall("there is a link to [[Kākapō|Kākapō parrot]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("there is a link to [[Māori people|Māori]] here"))
        self.assertEqual([], unmacroned_link_regex.findall("the [[Kākapō|Kākapō]] has a [[Whanāu|Whanāu]]"))

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
            alert_page='User:MacronMonitor/LinkAlerts',
            title='Test Page',
            user='Cloventt',
            revision={
                'old': 1234567,
                'new': 1234568,
            },
            reason="linkpipe over macrons from '''Kākapō, Whanāu'''"
        ))


if __name__ == '__main__':
    unittest.main()
