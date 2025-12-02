import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer (Windows Compatible)")
        self.root.geometry("900x600")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=30)
        self.text_area.grid(column=0, row=0, columnspan=3, padx=10, pady=10)

        tk.Label(root, text="Select Interface:").grid(row=1, column=0, sticky="w", padx=10)
        self.interface_box = ttk.Combobox(root, width=40)
        self.interface_box.grid(row=1, column=1, padx=10, pady=5)

        # Load interfaces
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            self.interface_box["values"] = interfaces
            if interfaces:
                self.interface_box.current(0)
        except:
            messagebox.showerror("Error", "Unable to load interfaces")

        self.start_button = tk.Button(root, text="Start Sniffing", bg="green", fg="white",
                                      width=20, command=self.start_sniffing)
        self.start_button.grid(column=0, row=2, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", bg="red", fg="white",
                                     width=20, state=tk.DISABLED, command=self.stop_sniffing)
        self.stop_button.grid(column=1, row=2, padx=10, pady=10)

        self.sniffing = False
        self.sniffer_thread = None

    def extract_info(self, pkt):
        info = ""
        if IP in pkt:
            info += f"Source IP      : {pkt[IP].src}\n"
            info += f"Destination IP : {pkt[IP].dst}\n"

        if TCP in pkt:
            info += "Protocol       : TCP\n"
            info += f"Source Port    : {pkt[TCP].sport}\n"
            info += f"Destination Port: {pkt[TCP].dport}\n"
        elif UDP in pkt:
            info += "Protocol       : UDP\n"
            info += f"Source Port    : {pkt[UDP].sport}\n"
            info += f"Destination Port: {pkt[UDP].dport}\n"
        elif ICMP in pkt:
            info += "Protocol       : ICMP\n"
        else:
            info += "Protocol       : Other\n"

        info += f"Packet Length  : {len(pkt)} bytes\n"
        return info

    def packet_callback(self, pkt):
        info = self.extract_info(pkt)
        self.text_area.insert(tk.END, info + "-"*80 + "\n")
        self.text_area.yview(tk.END)

    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.packet_callback, store=False, stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):
        iface = self.interface_box.get()
        if not iface:
            messagebox.showwarning("Warning", "Select an interface first!")
            return

        self.sniffing = True

        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True)
        self.sniffer_thread.start()

        self.text_area.insert(tk.END, f"Sniffing started on {iface}...\n")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_sniffing(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "Stopping sniffing...\n")

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()
