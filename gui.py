from sniffer_thread import SnifferThread
import customtkinter as ctk


class TCPSniperGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("TCP Sniper")
        self.root.geometry("800x600")

        # Internal state
        self.blacklist = set()
        self.packet_count = 0
        self.rst_packet_count = 0
        self.sniffer_thread = SnifferThread(self._packet_callback)

        # Create GUI components
        self._create_gui()

    def _create_gui(self):
        """Set up the basic layout of the GUI."""
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Blacklist section
        blacklist_frame = ctk.CTkFrame(main_frame)
        blacklist_frame.pack(side="left", fill="y", padx=(10, 0), pady=10)

        ctk.CTkLabel(
            blacklist_frame, text="Blacklist", font=("Arial", 16, "bold")
        ).pack(pady=5)
        self.blacklist_entry = ctk.CTkEntry(blacklist_frame, placeholder_text="Enter IP")
        self.blacklist_entry.pack(pady=5)
        ctk.CTkButton(
            blacklist_frame, text="Add", command=self._add_blacklist
        ).pack(pady=5)

        self.blacklist_display = ctk.CTkTextbox(blacklist_frame, height=300)
        self.blacklist_display.pack(padx=10, pady=10)

        # Sniffer control
        self.sniffer_button = ctk.CTkButton(
            blacklist_frame,
            text="Start Sniffing",
            command=self._toggle_sniffer,
            fg_color="green",
            hover_color="#005f00",
        )
        self.sniffer_button.pack(side="bottom", padx=10, pady=10)

        # Packet display
        packet_frame = ctk.CTkFrame(main_frame)
        packet_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            packet_frame, text="Captured Packets", font=("Arial", 16, "bold")
        ).pack(pady=5)
        self.packet_display = ctk.CTkTextbox(packet_frame)
        self.packet_display.pack(fill="both", expand=True, padx=10, pady=10)

    def _toggle_sniffer(self):
        """Start or stop the sniffer based on the current state."""
        if self.sniffer_button.cget("text") == "Start Sniffing":
            # Start the sniffer
            self._start_sniffer()
            self.sniffer_button.configure(
                text="Stop Sniffing",
                fg_color="red",
                hover_color="#8b0000",
            )
        else:
            # Stop the sniffer
            self._stop_sniffer()
            self.sniffer_button.configure(
                text="Start Sniffing",
                fg_color="green",
                hover_color="#005f00",
            )

    def _add_blacklist(self):
        """Add an IP to the blacklist."""
        ip = self.blacklist_entry.get().strip()
        if ip and ip not in self.blacklist:
            self.blacklist.add(ip)
            self.sniffer_thread.update_blacklist(self.blacklist)
            self.blacklist_display.insert("end", f"{ip}\n")
            self.blacklist_entry.delete(0, "end")

    def _start_sniffer(self):
        """Start the sniffer."""
        print("Sniffer started.")
        self.sniffer_thread.start_sniffer()

    def _stop_sniffer(self):
        """Stop the sniffer."""
        print("Sniffer stopped.")
        self.sniffer_thread.stop_sniffer()

    def _packet_callback(self, found_packet: str, to_src_packet: str, to_dst_packet: str):
        """Update the GUI with packet information."""
        self.packet_display.insert(
            "end",
            f"Found blacklist IP packet:\n{found_packet}\n"
            f"Sent fake RST to src packet:\n{to_src_packet}\n"
            f"Sent fake RST to dst packet:\n{to_dst_packet}\n\n",
        )
        self.packet_display.see("end")
        self.rst_packet_count += 1

    def run(self):
        """Run the GUI."""
        self.root.mainloop()
