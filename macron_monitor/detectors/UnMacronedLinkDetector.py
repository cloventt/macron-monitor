from typing import Optional

from macron_monitor import SuspiciousRev, module_logger
from macron_monitor.WPNZArticleProvider import WPNZArticleProvider
from macron_monitor.detectors import Detector

import re

unmacroned_link_regex = re.compile(r'\[\[([^\[\]<>{}]*?(?=[ĀĒĪŌŪāēīōū]+?)[^\[\]<>{}]*?)\|[^ĀĒĪŌŪāēīōū]*?]]')


class UnMacronedLinkDetector(Detector):

    _class_logger = module_logger.getChild(__qualname__)

    alert_page = 'User:MacronMonitor/LinkAlerts'

    def __init__(self,
                 wpnz_article_provider: WPNZArticleProvider,
                 ):
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.wpnz_article_provider = wpnz_article_provider

    def detect(self, change: dict, diff: dict) -> Optional[SuspiciousRev]:
        matches = self._flatten([unmacroned_link_regex.findall(hunk) for hunk in diff['added-context']])

        # filter only to links to articles within WPNZ
        # should filter out all the japanese and arabic articles
        wpnz_matches = filter(lambda m: m in self.wpnz_article_provider.article_titles, matches)
        if any(wpnz_matches):
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"linkpipe over macrons from '''{', '.join(sorted(list(set(matches))))}'''",
            )
