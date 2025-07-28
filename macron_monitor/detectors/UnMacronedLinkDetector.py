from typing import Optional

from macron_monitor import SuspiciousRev, module_logger, count_macrons, contains_macron
from macron_monitor.WPNZArticleProvider import WPNZArticleProvider
from macron_monitor.detectors import Detector

import re

link_regex = re.compile(r'\[\[([^\[\]<>{}]*?(?=[ĀĒĪŌŪāēīōū]+?)[^\[\]<>{}]*?)\|(.*?)]]')
unmacroned_link_regex = re.compile(r'\[\[([^\[\]<>{}]*?(?=[ĀĒĪŌŪāēīōū]+?)[^\[\]<>{}]*?)\|([^ĀĒĪŌŪāēīōū]*?)]]')


class UnMacronedLinkDetector(Detector):

    _class_logger = module_logger.getChild(__qualname__)

    alert_page = 'User:MacronMonitor/Alerts'

    def __init__(self,
                 wpnz_article_provider: WPNZArticleProvider,
                 ):
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.wpnz_article_provider = wpnz_article_provider

    def detect(self, change: dict, diff: dict) -> Optional[SuspiciousRev]:
        matches = self._flatten([link_regex.findall(hunk) for hunk in diff['added-context']])
        wpnz_matches = [m for m in matches if contains_macron(m[0]) and m[0] in self.wpnz_article_provider.article_titles]
        removed_macron_matches = sorted(list(set(m for m in wpnz_matches if count_macrons(m[0]) > count_macrons(m[1]))))

        alert_str = ', '.join([f'[[{m[0]}|{m[1]}]]' for m in removed_macron_matches])

        if any(wpnz_matches):
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"linkpipe over macrons in link to WPNZ article(s) '''(<nowiki>{alert_str}</nowiki>)'''",
            )
