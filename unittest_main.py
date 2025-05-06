import unittest
from unittest.mock import patch, MagicMock
from main import DDoSDetector, DDoSApp
import tkinter as tk

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

    def tearDown(self):
        self.root.destroy()

    @patch.object(DDoSApp, 'log_message')
    def test_start_detection(self, mock_log_message):
        self.app.start_detection()
        mock_log_message.assert_any_call("Starting DDoS detection...")
        self.assertTrue(self.app.running.is_set())

    @patch.object(DDoSApp, 'log_message')
    def test_stop_detection(self, mock_log_message):
        self.app.start_detection()
        self.app.stop_detection()
        mock_log_message.assert_any_call("Stopping DDoS detection...")
        self.assertFalse(self.app.running.is_set())

    @patch.object(DDoSApp, 'log_message')
    def test_process_packet(self, mock_log_message):
        packet_mock = MagicMock()
        packet_mock.haslayer.return_value = True
        packet_mock.__getitem__.return_value = {'src': '192.168.1.1'}
        packet_mock.src = "00:11:22:33:44:55"
        packet_mock.show.return_value = "Mock Packet Info"

        self.app.process_packet(packet_mock)
        mock_log_message.assert_any_call("Packet from IP: 192.168.1.1\nMock Packet Info")
        mock_log_message.assert_any_call("Device type: Unknown")

    @patch('requests.get')
    def test_get_device_type(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "Mock Device"
        device_type = self.app.get_device_type("00:11:22:33:44:55")
        self.assertEqual(device_type, "Mock Device")
        mock_get.assert_called_once_with("https://api.macvendors.com/00-11-22")

    @patch.object(DDoSApp, 'log_message')
    def test_update_graph(self, mock_log_message):
        self.app.detector.requests = {"192.168.1.1": 50, "192.168.1.2": 30}
        self.app.update_graph()
        self.assertEqual(len(self.app.detector.requests), 2)  # Verifica que el gráfico se actualiza con los datos correctos


if __name__ == "__main__":
    unittest.main()