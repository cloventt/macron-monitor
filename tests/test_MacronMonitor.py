import unittest

from macron_monitor import count_macrons
from macron_monitor.MacronMonitor import MacronMonitor


class test_MacronMonitor(unittest.TestCase):
    def test_macron_count(self):
        self.assertEqual(count_macrons("āēīōū"), 5)
        self.assertEqual(count_macrons("āēīōū", "āēīōū", "āēīōū", "āēīōū"), 20)

        self.assertEqual(count_macrons("ĀĒĪŌŪ"), 5)
        self.assertEqual(count_macrons("ĀĒĪŌŪ", "ĀĒĪŌŪ", "ĀĒĪŌŪ", "ĀĒĪŌŪ"), 20)

        self.assertEqual(count_macrons("david"), 0)
        self.assertEqual(count_macrons("david", "david", "david", "david"), 0)


if __name__ == '__main__':
    unittest.main()
