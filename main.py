import time
import threading
import tkinter as tk
from tkinter import ttk
from collections import defaultdict
from scapy.all import sniff

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
        self.root.geometry("400x300")
        self.root.configure(bg="#2c3e50")
        
        style = ttk.Style()
        style.configure("TLabel", background="#2c3e50", foreground="#ecf0f1", font=("Helvetica", 12))
        style.configure("TButton", background="#34495e", foreground="#ecf0f1", font=("Helvetica", 10))
        style.configure("TText", background="#34495e", foreground="#ecf0f1", font=("Helvetica", 10))
        
        self.label = ttk.Label(root, text="DDoS Detector")
        self.label.pack(pady=10)
        
        self.start_button = ttk.Button(root, text="Start Detection", command=self.start_detection)
        self.start_button.pack(pady=5)
        
        self.stop_button = ttk.Button(root, text="Stop Detection", command=self.stop_detection)
        self.stop_button.pack(pady=5)
        
        self.log = tk.Text(root, state='disabled', width=50, height=10, bg="#34495e", fg="#ecf0f1", font=("Helvetica", 10))
        self.log.pack(pady=10)
        
        self.running = False
        self.sniff_thread = None

    def start_detection(self):
        self.running = True
        self.log_message("Starting DDoS detection...")
        self.sniff_thread = threading.Thread(target=self.detect_ddos)
        self.sniff_thread.start()

    def stop_detection(self):
        self.running = False
        self.log_message("Stopping DDoS detection...")
        if self.sniff_thread is not None:
            self.sniff_thread.join()

    def detect_ddos(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.running)

    def process_packet(self, packet):
        if packet.haslayer('IP'):
            ip_address = packet['IP'].src
            self.detector.log_request(ip_address)
            print(f"Packet from IP: {ip_address}")  # Mostrar en consola
            if self.detector.is_ddos(ip_address):
                self.log_message(f"Possible DDoS attack detected from IP: {ip_address}")

    def log_message(self, message):
        self.log.config(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSApp(root)
    root.mainloop()