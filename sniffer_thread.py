# sniffer_thread.py

import threading
from sniffer import TCPSniffer
from typing import Callable, Optional


class SnifferThread:
    def __init__(self, callback: Callable[[bool, Optional[str]], None] = None):
        """
        Initialize the SnifferThread.

        :param callback: A function to call with packet information.
        """
        self.sniffer = TCPSniffer()
        self.callback = callback
        self.thread = None
        self.running = False

    def start_sniffer(self):
        """
        Start the sniffer in a new thread.
        """
        if self.thread and self.thread.is_alive():
            return  # Already running

        self.running = True
        self.thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self.thread.start()

    def _run_sniffer(self):
        """
        Internal method to run the sniffer.
        """
        self.sniffer.start_sniffing(callback=self.callback)

    def stop_sniffer(self):
        """
        Stop the sniffer.
        """
        self.sniffer.stop_sniffing()
        self.running = False
        if self.thread:
            self.thread.join()

    def update_blacklist(self, blacklist: set):
        """
        Update the sniffer's blacklist.

        :param blacklist: A set of blacklisted IPs.
        """
        self.sniffer.update_blacklist(blacklist)
