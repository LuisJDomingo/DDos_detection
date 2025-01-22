import unittest
from unittest.mock import patch
import time
from main import DDoSDetector, DDoSApp
import tkinter as tk

class TestDDoSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DDoSDetector(threshold=100, time_window=60)

    def test_log_request(self):
        ip_address = "192.168.1.1"
        self.detector.log_request(ip_address)
        self.assertEqual(len(self.detector.ip_access_times[ip_address]), 1)

    def test_cleanup_old_requests(self):
        ip_address = "192.168.1.1"
        self.detector.log_request(ip_address)
        time.sleep(1)
        self.detector.cleanup_old_requests(ip_address, time.time() + 61)
        self.assertEqual(len(self.detector.ip_access_times[ip_address]), 0)

    def test_is_ddos(self):
        ip_address = "192.168.1.1"
        for _ in range(101):
            self.detector.log_request(ip_address)
        self.assertTrue(self.detector.is_ddos(ip_address))

class TestDDoSApp(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = DDoSApp(self.root)

    @patch.object(DDoSApp, 'log_message')
    def test_start_detection(self, mock_log_message):
        self.app.start_detection()
        mock_log_message.assert_any_call("Starting DDoS detection...")

    @patch.object(DDoSApp, 'log_message')
    def test_stop_detection(self, mock_log_message):
        self.app.stop_detection()
        mock_log_message.assert_called_with("Stopping DDoS detection...")

    @patch.object(DDoSApp, 'log_message')
    def test_detect_ddos(self, mock_log_message):
        self.app.running = True
        self.app.detect_ddos()
        mock_log_message.assert_called_with("Possible DDoS attack detected from IP: 192.168.1.1")

if __name__ == "__main__":
    unittest.main()