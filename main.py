import time
from collections import defaultdict

class DDoSDetector:
    """
    A class used to detect potential DDoS attacks based on request frequency.
    Attributes
    ----------
    threshold : int
        The number of requests from a single IP address within the time window that will trigger a DDoS alert.
    time_window : int
        The time window in seconds during which requests are counted.
    ip_access_times : defaultdict
        A dictionary that maps IP addresses to a list of request timestamps.
    Methods
    -------
    log_request(ip_address)
        Logs a request from the given IP address and cleans up old requests.
    cleanup_old_requests(ip_address, current_time)
        Removes requests from the given IP address that are outside the time window.
    is_ddos(ip_address)
        Checks if the number of requests from the given IP address exceeds the threshold.
    """
    def __init__(self, threshold, time_window):
        self.threshold = threshold
        self.time_window = time_window
        self.ip_access_times = defaultdict(list)

    def log_request(self, ip_address):
        current_time = time.time()
        self.ip_access_times[ip_address].append(current_time)
        self.cleanup_old_requests(ip_address, current_time)

    def cleanup_old_requests(self, ip_address, current_time):
        self.ip_access_times[ip_address] = [
            timestamp for timestamp in self.ip_access_times[ip_address]
            if current_time - timestamp <= self.time_window
        ]

    def is_ddos(self, ip_address):
        return len(self.ip_access_times[ip_address]) > self.threshold

if __name__ == "__main__":
    detector = DDoSDetector(threshold=100, time_window=60)  # 100 requests per minute

    # Simulación de solicitudes
    test_ip = "192.168.1.1"
    for _ in range(105):
        detector.log_request(test_ip)
        if detector.is_ddos(test_ip):
            print(f"Possible DDoS attack detected from IP: {test_ip}")
            break
        time.sleep(0.5)