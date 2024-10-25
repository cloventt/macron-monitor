from abc import abstractmethod

from macron_monitor import SuspiciousRev


class Detector:

    @abstractmethod
    def detect(self, change_message: dict, diff: dict) -> SuspiciousRev:
        raise NotImplementedError()
