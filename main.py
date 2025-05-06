import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests

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
        self.root.title("DDoS Detection System")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
        self.running = threading.Event()
        self.sniff_thread = None
        self.detector = DDoSDetector()  # Inicializa el detector aquí

        # Configuración del log
        self.log_frame = ttk.LabelFrame(root, text="Log", padding=(10, 5))
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.log = tk.Text(self.log_frame, height=10, state='disabled', bg="#e0e0e0")
        self.log.pack(fill="both", expand=True)

        # Configuración de los botones
        self.button_frame = ttk.Frame(root, padding=(10, 5))
        self.button_frame.pack(fill="x", padx=10, pady=5)
        self.start_button = ttk.Button(self.button_frame, text="Start Detection", command=self.start_detection)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(self.button_frame, text="Stop Detection", command=self.stop_detection)
        self.stop_button.pack(side="left", padx=5)

        # Configuración del gráfico
        self.graph_frame = ttk.LabelFrame(root, text="Traffic Analysis", padding=(10, 5))
        self.graph_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def log_message(self, message):
        self.log.config(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.config(state='disabled')
        self.log.see(tk.END)

    def start_detection(self):
        self.running.set()
        self.log_message("Starting DDoS detection...")
        self.sniff_thread = threading.Thread(target=self.detect_ddos)
        self.sniff_thread.start()

    def stop_detection(self):
        self.log_message("Stopping DDoS detection...")
        self.running.clear()
        if self.sniff_thread is not None:
            self.sniff_thread.join(timeout=10)  # Espera un máximo de 10 segundos para que el hilo termine
            if self.sniff_thread.is_alive():
                self.log_message("Failed to stop DDoS detection thread.")
            else:
                self.sniff_thread = None
                self.log_message("DDoS detection stopped.")

    def detect_ddos(self):
        try:
            sniff(prn=self.process_packet, stop_filter=lambda x: not self.running.is_set(), iface="Wi-Fi 3")
        except Exception as e:
            self.log_message(f"Error in sniffing: {e}")

    # @patch.object(DDoSApp, 'log_message')
    def test_process_packet(self, mock_log_message):
        # Crear un mock para el paquete
        packet_mock = MagicMock()
        packet_mock.haslayer.return_value = True  # Simula que el paquete tiene una capa 'IP'
        packet_mock.__getitem__.return_value = MagicMock(src="192.168.1.1")  # Simula el acceso a packet['IP']
        packet_mock.src = "00:11:22:33:44:55"  # Dirección MAC simulada
        packet_mock.show.return_value = "Mock Packet Info"  # Información simulada del paquete

        # Llamar al método process_packet con el mock
        self.app.process_packet(packet_mock)

        # Verificar que los mensajes de log se llamaron correctamente
        mock_log_message.assert_any_call("Packet from IP: 192.168.1.1\nMock Packet Info")
        mock_log_message.assert_any_call("Device type: Unknown")

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