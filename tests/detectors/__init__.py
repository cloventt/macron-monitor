from macron_monitor.WPNZArticleProvider import WPNZArticleProvider


class MockWPNZArticleProvider(WPNZArticleProvider):

    def __init__(self):
        pass

    article_titles = set()
