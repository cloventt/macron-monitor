from macron_monitor import SuspiciousRev, count_macrons
from macron_monitor.detectors import Detector


class RemovedMacronDetector(Detector):

    alert_page = 'User:MacronMonitor/Alerts'

    def detect(self, change: dict, diff: dict) -> SuspiciousRev:
        deleted_macrons = count_macrons(*diff['deleted-context'])
        added_macrons = count_macrons(*diff['added-context'])

        if deleted_macrons > added_macrons:
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"removed '''{deleted_macrons - added_macrons}''' macron(s)",
            )

