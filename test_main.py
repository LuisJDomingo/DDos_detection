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
        class TestDDoSDetector(unittest.TestCase):
            def setUp(self):
                self.detector = DDoSDetector()

            def test_log_request(self):
                ip_address = "192.168.1.1"
                self.detector.log_request(ip_address)
                self.assertEqual(self.detector.requests[ip_address], 1)

            def test_multiple_log_requests(self):
                ip_address = "192.168.1.1"
                for _ in range(5):
                    self.detector.log_request(ip_address)
                self.assertEqual(self.detector.requests[ip_address], 5)

            def test_is_ddos(self):
                ip_address = "192.168.1.1"
                for _ in range(101):
                    self.detector.log_request(ip_address)
                self.assertTrue(self.detector.is_ddos(ip_address))

            def test_is_not_ddos(self):
                ip_address = "192.168.1.1"
                for _ in range(50):
                    self.detector.log_request(ip_address)
                self.assertFalse(self.detector.is_ddos(ip_address))


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
                self.app.running.set()
                self.app.detector.log_request("192.168.1.1")
                self.app.detector.log_request("192.168.1.1")
                self.app.detector.log_request("192.168.1.1")
                self.app.detector.requests["192.168.1.1"] = 101  # Simulate DDoS
                self.app.detect_ddos()
                mock_log_message.assert_any_call("Possible DDoS attack detected from IP: 192.168.1.1")

            @patch.object(DDoSApp, 'log_message')
            def test_process_packet(self, mock_log_message):
                packet_mock = type('Packet', (object,), {
                    'haslayer': lambda self, layer: layer == 'IP',
                    'src': '00:11:22:33:44:55',
                    'show': lambda self, dump: "Mock Packet Info",
                    '__getitem__': lambda self, key: {'src': '192.168.1.1'} if key == 'IP' else None
                })()
                self.app.process_packet(packet_mock)
                mock_log_message.assert_any_call("Packet from IP: 192.168.1.1\nMock Packet Info")

            @patch.object(DDoSApp, 'log_message')
            def test_get_device_type(self, mock_log_message):
                with patch('requests.get') as mock_get:
                    mock_get.return_value.status_code = 200
                    mock_get.return_value.text = "Mock Device"
                    device_type = self.app.get_device_type("00:11:22:33:44:55")
                    self.assertEqual(device_type, "Mock Device")
                    mock_get.assert_called_once_with("https://api.macvendors.com/00-11-22")

            @patch.object(DDoSApp, 'log_message')
            def test_update_graph(self, mock_log_message):
                self.app.detector.requests = {"192.168.1.1": 50, "192.168.1.2": 30}
                self.app.update_graph()
                self.assertEqual(len(self.app.detector.requests), 2)  # Ensure graph updates with correct data


        if __name__ == "__main__":
            unittest.main()
        self.app.detect_ddos()
        mock_log_message.assert_called_with("Possible DDoS attack detected from IP: 192.168.1.1")

if __name__ == "__main__":
    unittest.main()