import threading
import tkinter as tk
from scapy.all import sniff, conf
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests
import socket

class DDoSDetector:
    def __init__(self):
        self.requests = {}

    def log_request(self, ip_address):
        if ip_address in self.requests:
            self.requests[ip_address] += 1
        else:
            self.requests[ip_address] = 1

    def is_ddos(self, ip_address):
        return self.requests.get(ip_address, 0) > 100  # Ejemplo de umbral

class DDoSApp:
    def __init__(self, root):
        self.root = root
        self.running = False
        self.sniff_thread = None
        self.detector = DDoSDetector()  # Inicializa el detector aquí
        self.log = tk.Text(root)
        self.log.pack()
        self.start_button = tk.Button(root, text="Start Detection", command=self.start_detection)
        self.start_button.pack()
        self.stop_button = tk.Button(root, text="Stop Detection", command=self.stop_detection)
        self.stop_button.pack()
        
        # Configuración del gráfico
        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.figure, master=root)
        self.canvas.get_tk_widget().pack()

    def log_message(self, message):
        self.log.config(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.config(state='disabled')

    def start_detection(self):
        self.running = True
        self.log_message("Starting DDoS detection...")
        self.sniff_thread = threading.Thread(target=self.detect_ddos)
        self.sniff_thread.start()

    def stop_detection(self):
        self.log_message("Stopping DDoS detection...")
        self.running = False
        if self.sniff_thread is not None:
            # Enviar un paquete vacío para detener el sniff
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b'', ('127.0.0.1', 0))
            self.sniff_thread.join(timeout=10)  # Espera un máximo de 10 segundos para que el hilo termine
            if self.sniff_thread.is_alive():
                self.log_message("Failed to stop DDoS detection thread.")
            else:
                self.sniff_thread = None
                self.log_message("DDoS detection stopped.")

    def detect_ddos(self):
        try:
            sniff(prn=self.process_packet, stop_filter=lambda x: not self.running, iface="Wi-Fi 3")
        except Exception as e:
            self.log_message(f"Error in sniffing: {e}")

    def process_packet(self, packet):
        if packet.haslayer('IP'):
            ip_address = packet['IP'].src
            mac_address = packet.src
            self.detector.log_request(ip_address)
            packet_info = packet.show(dump=True)
            self.log_message(f"Packet from IP: {ip_address}\n{packet_info}")
            print(f"Packet from IP: {ip_address}")
            print(packet_info)
            if self.detector.is_ddos(ip_address):
                self.log_message(f"Possible DDoS attack detected from IP: {ip_address}")
            device_type = self.get_device_type(mac_address)
            self.log_message(f"Device type: {device_type}")
            self.update_graph()

    def get_device_type(self, mac_address):
        oui = mac_address[:8].upper().replace(':', '-')
        try:
            response = requests.get(f"https://api.macvendors.com/{oui}")
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown"
        except requests.RequestException as e:
            self.log_message(f"Error fetching device type: {e}")
            return "Unknown"

    def update_graph(self):
        self.ax.clear()
        ip_addresses = list(self.detector.requests.keys())
        request_counts = list(self.detector.requests.values())
        self.ax.bar(ip_addresses, request_counts)
        self.ax.set_xlabel('IP Address')
        self.ax.set_ylabel('Number of Requests')
        self.ax.set_title('Traffic Analysis')
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSApp(root)
    root.mainloop()