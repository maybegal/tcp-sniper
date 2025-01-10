# gui.py

import customtkinter as ctk
from main import TCPSniffer
import threading
import ipaddress
from datetime import datetime
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TCPSniperGUI:
    def __init__(self):
        # Setup window
        self.root = ctk.CTk()
        self.root.title("TCP Sniper")
        self.root.geometry("1000x600")

        # Variables
        self.sniffing = False
        self.blacklist = set()
        self.sniffer = TCPSniffer(callback=self._handle_packet)

        # Create GUI
        self._create_gui()

    def _create_gui(self):
        # Main container with padding
        container = ctk.CTkFrame(self.root)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        container.grid_columnconfigure(1, weight=1)  # Right panel expands
        container.grid_rowconfigure(0, weight=1)  # Both panels expand vertically

        # Left panel
        left_panel = ctk.CTkFrame(container, width=400)
        left_panel.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        left_panel.grid_propagate(False)  # Maintain width

        # Blacklist section
        self._create_blacklist_section(left_panel)

        # Start button at bottom of left panel
        self.start_button = ctk.CTkButton(
            left_panel,
            text="Start Sniffing",
            command=self._toggle_sniffing,
            fg_color="green",
            height=35
        )
        self.start_button.pack(side="bottom", fill="x", padx=15, pady=15)

        # Right panel
        right_panel = ctk.CTkFrame(container)
        right_panel.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)

        # Packet display header
        header = ctk.CTkFrame(right_panel)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="Captured Packets",
            font=("Arial", 14, "bold")
        ).pack()

        self.packet_count = ctk.CTkLabel(header, text="Total captured packets: 0, Total TCP network packets: 0")
        self.packet_count.pack()

        # Packet display
        self.packet_display = ctk.CTkTextbox(
            right_panel,
            font=("Courier", 14)
        )
        self.packet_display.pack(fill="both", expand=True)

    def _create_blacklist_section(self, parent):
        # Title
        ctk.CTkLabel(
            parent,
            text="Blacklist",
            font=("Open-Sans", 16, "bold")
        ).pack(pady=(10, 0))

        # Description
        ctk.CTkLabel(
            parent,
            text="TCP terminate connection address targets.",
            font=("Open-Sans", 14)
        ).pack(padx=15, pady=(0, 10))

        # IP input frame
        input_frame = ctk.CTkFrame(parent)
        input_frame.pack(fill="x", pady=10)

        self.ip_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter IPv4 address"
        )
        self.ip_entry.pack(side="left", fill="x", expand=True, padx=(15, 0))

        add_btn = ctk.CTkButton(
            input_frame,
            text="+",
            width=30,
            font=("Arial", 20),
            command=self._add_ip
        )
        add_btn.pack(side="right", padx=(0, 15))

        # Blacklist display
        self.blacklist_display = ctk.CTkScrollableFrame(
            parent,
            height=300
        )
        self.blacklist_display.pack(fill="x", pady=15, padx=15)

    def _add_ip(self):
        ip = self.ip_entry.get().strip()
        try:
            ipaddress.ip_address(ip)
            if ip not in self.blacklist:
                self.blacklist.add(ip)
                self._create_ip_entry(ip)
                self.ip_entry.delete(0, "end")
                self.sniffer.update_blacklist(self.blacklist)
            else:
                self._log_message(f"IP {ip} already in blacklist")
        except ValueError:
            self._log_message(f"Invalid IP: {ip}")

    def _create_ip_entry(self, ip):
        # Frame for IP and remove button
        frame = ctk.CTkFrame(self.blacklist_display)
        frame.pack(fill="x")

        # IP label
        ctk.CTkLabel(
            frame,
            text=ip,
            anchor="w"
        ).pack(side="left", padx=5, fill="x", expand=True)

        # Remove button
        remove_btn = ctk.CTkButton(
            frame,
            text="×",
            width=25,
            height=25,
            fg_color="red",
            font=("Arial", 20, "bold"),
            command=lambda: self._remove_ip(ip, frame)
        )
        remove_btn.pack(side="right", padx=5)

    def _remove_ip(self, ip, frame):
        self.blacklist.remove(ip)
        frame.destroy()
        self.sniffer.update_blacklist(self.blacklist)

    def _toggle_sniffing(self):
        if not self.sniffing:
            if not self.blacklist:
                self._log_message("Please add at least one IP to blacklist")
                return

            self.sniffing = True
            self.start_button.configure(
                text="Stop Sniffing",
                fg_color="red"
            )

            # Start sniffing thread
            threading.Thread(
                target=self.sniffer.start_sniffing,
                daemon=True
            ).start()

            self._log_message("Sniffing started")
        else:
            self.sniffing = False
            self.start_button.configure(
                text="Start Sniffing",
                fg_color="green"
            )
            self.sniffer.stop_sniffing()
            self._log_message("Sniffing stopped")

    def _handle_packet(self, packet: Packet):
        try:
            # Extract packet info
            ip = packet[IP]
            tcp = packet[TCP]

            # Create readable packet entry
            timestamp = datetime.now().strftime("%H:%M:%S")
            entry = (
                f"\n[{timestamp}] Packet Captured\n"
                f"{'=' * 40}\n"
                f"From: {ip.src}:{tcp.sport}\n"
                f"To:   {ip.dst}:{tcp.dport}\n"
                f"{'=' * 40}\n"
            )

            # Update UI (thread-safe)
            self.root.after(0, self._update_display, entry)

        except Exception as e:
            self._log_message(f"Error processing packet: {e}")

    def _update_display(self, entry):
        # Update packet display
        self.packet_display.insert("end", entry)
        self.packet_display.see("end")

        # Update packet counter
        count = int(self.packet_count.cget("text").split(": ")[1]) + 1
        self.packet_count.configure(text=f"Total: {count}")

    def _log_message(self, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"\n[{timestamp}] {message}\n"
        self.packet_display.insert("end", entry)
        self.packet_display.see("end")

    def run(self):
        try:
            self.root.mainloop()
        finally:
            if self.sniffing:
                self.sniffer.stop_sniffing()


def main():
    app = TCPSniperGUI()
    app.run()


if __name__ == "__main__":
    main()