from macron_monitor import SuspiciousRev
from macron_monitor.detectors import Detector

import re

unmacroned_link_regex = re.compile(r'\[\[([^\[]*?(?=[ĀĒĪŌŪāēīōū]+?)[^\[\]]*?)\|[^ĀĒĪŌŪāēīōū]*?]]')


class UnMacronedLinkDetector(Detector):

    alert_page = 'User:MacronMonitor/LinkAlerts'

    @staticmethod
    def flatten(xss):
        return [x for xs in xss for x in xs]

    def detect(self, change: dict, diff: dict) -> SuspiciousRev:
        matches = self.flatten([unmacroned_link_regex.findall(hunk) for hunk in diff['added-context']])
        if any(matches):
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"link descriptions overwrite macrons from '''{', '.join(sorted(list(set(matches))))}'''",
            )

