import json
import logging
import time
from pathlib import Path
from typing import List

import click
import pywikibot
from prometheus_client import start_http_server, Summary, Counter, Gauge
from pywikibot import diff
from pywikibot.bot import SingleSiteBot
from pywikibot.comms.eventstreams import EventStreams

from macron_monitor import SUSPICIOUS_WORDS, module_logger, SuspiciousRev
from macron_monitor.detectors import Detector
from macron_monitor.detectors.RemovedMacronDetector import RemovedMacronDetector
from macron_monitor.detectors.UnMacronedLinkDetector import UnMacronedLinkDetector

HANDLE_TIME = Summary('change_processing_seconds', 'Time spent processing a change')
DETECTIONS_COUNT = Counter('suspicious_edits_detected', 'Suspicious edits detected')
SUCCESSFUL_ALERT_PAGE_UPDATE_COUNT = Counter('alert_page_edit_successful', 'Successful edits to the alert page')
STREAM_LAG = Gauge('change_stream_lag_seconds',
                   'Difference in seconds between wallclock and most recently processed record timestamp')


class MacronMonitor(SingleSiteBot):
    _class_logger = module_logger.getChild(__qualname__)

    detectors: List[Detector] = [
        RemovedMacronDetector(),
        UnMacronedLinkDetector(),
    ]

    def __init__(self, **kwargs) -> None:
        self._instance_logger = self._class_logger.getChild(str(id(self)))

        super().__init__(**kwargs)

        self.site = pywikibot.Site('en', 'wikipedia', user='MacronMonitor')
        self.site.login()

        self.stream = EventStreams(
            streams=['recentchange', 'revision-create'],
            since=self.site.getcurrenttimestamp(),
        )

    def run(self) -> None:
        self.stream.register_filter(server_name='en.wikipedia.org', type='edit', namespace=0, bot=False)
        while True:
            change = next(iter(self.stream))
            self._handle_change(change)

    @HANDLE_TIME.time()
    def _handle_change(self, change):
        try:
            STREAM_LAG.set(time.time() - change['timestamp'])
            self._instance_logger.debug('Detected a change to [[%s]] (%s) by %s', change['title'], change['notify_url'],
                                        change['user'])
            html_diff = self.site.compare(old=change['revision']['old'], diff=change['revision']['new'])
            parsed_diff = diff.html_comparator(html_diff)
            self._instance_logger.debug('Collected a diff: %s', parsed_diff)

            detected_issues = [detector.detect(change, parsed_diff) for detector in self.detectors]

            if any(detected_issues):
                DETECTIONS_COUNT.inc()
                for suspicious_rev in detected_issues:
                    if suspicious_rev is None:
                        continue
                    print(suspicious_rev.to_string())
                    self._update_alert_list(suspicious_rev)

        except pywikibot.exceptions.APIError as apierror:
            self._instance_logger.error("Received an exception connecting to the Wikimedia API", exc_info=apierror)

    def _update_alert_list(self, alert_data: SuspiciousRev) -> None:
        page = pywikibot.Page(self.site,
                              #alert_data.alert_page,
                              'User:MacronMonitor/Alerts'
                              )
        current_list = page.get()

        new_content = current_list.replace('==Alerts==\n', f'==Alerts==\n{alert_data.to_string()}\n')
        page.text = new_content
        page.save(
            summary=f"add alert for edit on page [[{alert_data.title}]]",
            bot=False,  # mark as not a bot edit so it appears in user watchlists
            minor=False,
        )
        self._instance_logger.info("Added the alert to the alert page")

    @staticmethod
    def suspicious_words(*strings: str) -> int:
        words = [context.split() for contexts in strings for context in contexts]  # ouch my brain
        return any([word in SUSPICIOUS_WORDS for word in words])


@click.command()
@click.option('--log-level', default='INFO', help='Level to use for logging to console')
@click.option('--oauth-consumer-token', help='Consumer token for login')
@click.option('--oauth-consumer-secret', help='Consumer secret for login')
@click.option('--oauth-access-token', help='Access token for login')
@click.option('--oauth-access-secret', help='Access secret for login')
@click.option('--oauth-creds-file', help='file in present working directory that contains oauth creds',
              default="oauth-creds.json")
def run(log_level, oauth_consumer_token, oauth_consumer_secret, oauth_access_token, oauth_access_secret, oauth_creds_file):
    """Simple program that greets NAME for a total of COUNT times."""
    try:
        log_handler = logging.StreamHandler()
        log_handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s',
                                      datefmt="%Y-%m-%dT%H:%M:%S%z")
        log_handler.setFormatter(formatter)
        module_logger.addHandler(log_handler)
        module_logger.setLevel(log_level)

        if Path(oauth_creds_file).exists():
            with open(oauth_creds_file, 'r') as creds_file:
                creds = json.load(creds_file)
        else:
            creds = dict()

        creds['consumer_token'] = oauth_consumer_token if oauth_consumer_token else creds['consumer_token']
        creds['consumer_secret'] = oauth_consumer_secret if oauth_consumer_secret else creds['consumer_secret']
        creds['access_token'] = oauth_access_token if oauth_access_token else creds['access_token']
        creds['access_secret'] = oauth_access_secret if oauth_access_secret else creds['access_secret']

        authentication = (creds['consumer_token'], creds['consumer_secret'], creds['access_token'], creds['access_secret'])

        pywikibot.config.usernames['wikipedia']['en'] = 'MacronMonitor'
        pywikibot.config.authenticate['en.wikipedia.org'] = authentication

        start_http_server(8420)

        bot = MacronMonitor()
        bot.run()
    except KeyboardInterrupt as e:
        module_logger.error("Got asked to exit! I am now dying X_X")


if __name__ == '__main__':
    run()
