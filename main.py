# main.py


from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


def terminate_connection(packet: Packet) -> None:
    """
    Terminates a TCP connection by sending RST packets to both the source and destination addresses.
    """

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    # Create an RST packet for the source.
    to_src_packet = IP(src=ip_layer.dst, dst=ip_layer.src) / TCP(sport=tcp_layer.dst, dport=tcp_layer.src, flags="R", seq=tcp_layer.ack)

    # Create an RST packet for the destination.
    to_dst_packet = IP(src=ip_layer.src, dst=ip_layer.dst) / TCP(sport=ip_layer.src, dport=tcp_layer.dst, flags="R", seq=tcp_layer.seq)

    # Send the RST packets.
    send(to_src_packet, verbose=False)
    send(to_dst_packet, verbose=False)


def handle_packet(packet: Packet, blacklist: list[str]) -> None:
    """
    Handles sniffed packet, shows to GUI, resets the connection.
    """

    # Filter to only packet with IP and TCP layers.
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    # Filter to only packet with blacklist IP source or destination addresses.
    if (packet[IP].src not in blacklist) and (packet[IP].dst not in blacklist):
        return

    # Filter to only ACK packets.
    if packet[TCP].flags != "A":
        return

    print(packet)   # GUI in the future.

    terminate_connection(packet)


def start_sniffing(blacklist: list[str]) -> None:
    """
    Start sniffing the network and process each packet.
    """
    print("Starting network sniffing...")  # GUI in the future.

    sniff(
        filter="tcp",
        prn=lambda packet: handle_packet(packet, blacklist),
    )


def main() -> None:
    blacklist = ["10.14.51.241"]
    start_sniffing(blacklist)


if __name__ == '__main__':
    main()
