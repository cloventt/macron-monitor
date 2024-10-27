import logging
from typing import Optional

from macron_monitor import SuspiciousRev, count_macrons, module_logger
from macron_monitor.WPNZArticleProvider import WPNZArticleProvider
from macron_monitor.detectors import Detector


class RemovedMacronDetector(Detector):

    _class_logger = module_logger.getChild(__qualname__)

    alert_page = 'User:MacronMonitor/Alerts'

    def __init__(self,
                 wpnz_article_provider: WPNZArticleProvider,
                 ):
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.wpnz_article_provider = wpnz_article_provider

    def detect(self, change: dict, diff: dict) -> Optional[SuspiciousRev]:
        if change['title'] not in self.wpnz_article_provider.article_titles:
            self._instance_logger.debug("Article is not within WPNZ, skipping it")
            return

        deleted_macrons = count_macrons(*diff['deleted-context'])
        added_macrons = count_macrons(*diff['added-context'])

        if deleted_macrons > added_macrons:
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"removed '''{deleted_macrons - added_macrons}''' macron(s) from a WPNZ article",
            )
