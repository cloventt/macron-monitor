import dataclasses
import logging

module_logger = logging.getLogger(__name__)

MACRONS = ['ā', 'ē', 'ī', 'ō', 'ū']


@dataclasses.dataclass()
class SuspiciousRev:
    alert_page: str
    title: str
    user: str
    revision: dict
    reason: str

    def to_string(self):
        return f"* ~~~~~ ({{{{diff2|{self.revision['new']}|diff}}}}) — '''[[{self.title}]]''' — [[User:{self.user}|{self.user}]] ([[User_talk:{self.user}|talk]] | [[Special:Contributions/{self.user}|contribs]]) — reason: ''{self.reason}''"


def count_macrons(*string: str) -> int:
    strings = str.join('', string).lower()
    return sum([strings.count(c) for c in MACRONS])
