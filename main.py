# main.py

from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from typing import Callable, Optional, Set


class TCPSniffer:
    def __init__(self, callback: Optional[Callable[[Packet], None]] = None):
        """
        Initialize the TCP Sniffer.

        Args:
            callback: Optional function to be called when a packet is processed
        """
        self.callback = callback
        self.blacklist: Set[str] = set()
        self.is_running = False

    def terminate_connection(self, packet: Packet) -> None:
        """
        Terminates a TCP connection by sending RST packets to both the source and destination addresses.
        """
        try:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            # Create an RST packet for the source
            to_src_packet = IP(src=ip_layer.dst, dst=ip_layer.src) / TCP(
                sport=tcp_layer.dport,
                dport=tcp_layer.sport,
                flags="R",
                seq=tcp_layer.ack
            )

            # Create an RST packet for the destination
            to_dst_packet = IP(src=ip_layer.src, dst=ip_layer.dst) / TCP(
                sport=tcp_layer.sport,
                dport=tcp_layer.dport,
                flags="R",
                seq=tcp_layer.seq
            )

            # Send the RST packets
            send(to_src_packet, verbose=False)
            send(to_dst_packet, verbose=False)

        except Exception as e:
            if self.callback:
                self.callback(f"Error terminating connection: {str(e)}")

    def handle_packet(self, packet: Packet) -> None:
        """
        Handles sniffed packet, shows to GUI, resets the connection.
        """
        try:
            # Filter to only packet with IP and TCP layers
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return

            # Filter to only packet with blacklist IP source or destination addresses
            if (packet[IP].src not in self.blacklist) and (packet[IP].dst not in self.blacklist):
                return

            # Filter to only ACK packets
            if packet[TCP].flags != "A":
                return

            # Call the callback function if provided
            if self.callback:
                self.callback(packet)

            self.terminate_connection(packet)

        except Exception as e:
            if self.callback:
                self.callback(f"Error handling packet: {str(e)}")

    def start_sniffing(self) -> None:
        """
        Start sniffing the network and process each packet.
        """
        try:
            self.is_running = True
            sniff(
                filter="tcp",
                prn=self.handle_packet,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            if self.callback:
                self.callback(f"Error starting sniffer: {str(e)}")

    def stop_sniffing(self) -> None:
        """
        Stop the sniffing process.
        """
        self.is_running = False

    def update_blacklist(self, blacklist: Set[str]) -> None:
        """
        Update the blacklist of IP addresses.
        """
        self.blacklist = blacklist


def main() -> None:
    """
    Main function for standalone usage without GUI.
    """

    def print_callback(packet):
        print(packet)

    sniffer = TCPSniffer(callback=print_callback)
    sniffer.update_blacklist({"10.14.51.241"})
    try:
        print("Starting network sniffing...")
        sniffer.start_sniffing()
    except KeyboardInterrupt:
        print("\nStopping network sniffing...")
        sniffer.stop_sniffing()


if __name__ == '__main__':
    main()