import time
import tkinter as tk
from collections import defaultdict

class DDoSDetector:
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

class DDoSApp:
    def __init__(self, root):
        self.detector = DDoSDetector(threshold=100, time_window=60)
        self.root = root
        self.root.title("DDoS Detector")
        
        self.label = tk.Label(root, text="DDoS Detector")
        self.label.pack()
        
        self.start_button = tk.Button(root, text="Start Detection", command=self.start_detection)
        self.start_button.pack()
        
        self.stop_button = tk.Button(root, text="Stop Detection", command=self.stop_detection)
        self.stop_button.pack()
        
        self.log = tk.Text(root, state='disabled', width=50, height=10)
        self.log.pack()
        
        self.running = False

    def start_detection(self):
        self.running = True
        self.log_message("Starting DDoS detection...")
        self.detect_ddos()

    def stop_detection(self):
        self.running = False
        self.log_message("Stopping DDoS detection...")

    def detect_ddos(self):
        if self.running:
            test_ip = "192.168.1.1"
            for _ in range(105):
                self.detector.log_request(test_ip)
                if self.detector.is_ddos(test_ip):
                    self.log_message(f"Possible DDoS attack detected from IP: {test_ip}")
                    break
                time.sleep(0.5)
            self.root.after(1000, self.detect_ddos)

    def log_message(self, message):
        self.log.config(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSApp(root)
    root.mainloop()

    # Simulación de solicitudes
    test_ip = "192.168.1.1"
    for _ in range(105):
        detector.log_request(test_ip)
        if detector.is_ddos(test_ip):
            print(f"Possible DDoS attack detected from IP: {test_ip}")
            break
        time.sleep(0.5)