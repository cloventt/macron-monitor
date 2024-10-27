from abc import abstractmethod
from typing import Optional

from macron_monitor import SuspiciousRev


class Detector:

    @staticmethod
    def _flatten(xss):
        return [x for xs in xss for x in xs]

    @abstractmethod
    def detect(self, change_message: dict, diff: dict) -> Optional[SuspiciousRev]:
        raise NotImplementedError()
