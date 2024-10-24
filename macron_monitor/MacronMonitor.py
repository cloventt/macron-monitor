import dataclasses
import json
import logging
import time
from typing import Union, List

import pywikibot
from pywikibot import diff
from pywikibot.bot import SingleSiteBot
from pywikibot.comms.eventstreams import EventStreams

from prometheus_client import start_http_server, Summary, Counter, Gauge

from macron_monitor import SUSPICIOUS_WORDS

macrons = ['ā', 'ē', 'ī', 'ō', 'ū']

HANDLE_TIME = Summary('change_processing_seconds', 'Time spent processing a change')
DETECTIONS_COUNT = Counter('suspicious_edits_detected', 'Suspicious edits detected')
STREAM_LAG = Gauge('change_stream_lag_seconds',
                   'Difference in seconds between wallclock and most recently processed record timestamp')


class MacronMonitor(SingleSiteBot):

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.site = pywikibot.Site('en', 'wikipedia')

        self.stream = EventStreams(
            streams=['recentchange', 'revision-create'],
            since=self.site.getcurrenttimestamp(),
        )

    def run(self) -> None:
        self.stream.register_filter(server_name='en.wikipedia.org', type='edit', namespace=0, bot=False)
        while True:
            if int(time.time()) % 60 == 0:
                logging.info('Records processed: %f', DETECTIONS_COUNT.collect())
            change = next(iter(self.stream))
            self._handle_change(change)

    @HANDLE_TIME.time()
    def _handle_change(self, change):
        STREAM_LAG.set(time.time() - change['timestamp'])
        html_diff = self.site.compare(old=change['revision']['old'], diff=change['revision']['new'])
        parsed_diff = diff.html_comparator(html_diff)

        deleted_macrons = self.count_macrons(*parsed_diff['deleted-context'])
        added_macrons = self.count_macrons(*parsed_diff['added-context'])

        if deleted_macrons > added_macrons:
            rev_data = DeletedMacronRev(
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                added=added_macrons,
                removed=deleted_macrons
            )
            pywikibot.info('Detected a suspicious edit', rev_data)
            DETECTIONS_COUNT.inc()
        else:
            pywikibot.debug('skip')

    @staticmethod
    def count_macrons(*string: str) -> int:
        strings = str.join('', string).lower()
        return sum([strings.count(c) for c in macrons])

    @staticmethod
    def suspicious_words(*strings: str) -> int:
        words = [context.split() for contexts in strings for context in contexts]  # ouch my brain
        return any([word in SUSPICIOUS_WORDS for word in words])


if __name__ == '__main__':
    start_http_server(8420)
    bot = MacronMonitor()
    bot.run()


@dataclasses.dataclass()
class DeletedMacronRev:
    title: str
    user: str
    revision: dict
    added: int
    removed: int


@dataclasses.dataclass()
class MisspelledWordRev:
    title: str
    user: str
    revision: dict
    word: str
