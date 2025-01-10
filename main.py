# main.py


from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet


def terminate_connection(packet: Packet) -> None:
    """Sends RST packet to both source and destination addresses."""

    ip_address_src, port_src = packet[IP].src, packet[TCP].sport
    ip_address_dst, port_dst = packet[IP].dst, packet[TCP].dport
    seq = packet[TCP].seq
    ack = packet[TCP].ack

    # Create source and destination packets
    src_packet = Ether() / IP(dst=ip_address_src / TCP(sport=port_dst, dport=port_src, flags="R", seq=ack))
    dst_packet = Ether() / IP(dst=ip_address_dst) / TCP(sport=port_src, dport=port_dst, flags="R", seq=seq)

    # Send packets
    send(src_packet)
    send(dst_packet)


def handle_packet(packet: Packet, blacklist: list[str]) -> None:
    """Handles sniffed packet, shows to GUI, resets the connection."""

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    # Filter to only packet in blacklist IP addresses.
    if (packet[IP].src not in blacklist) and (packet[IP].dst not in blacklist):
        return

    # if (packet[TCP].flags != "A"):
    #     return

    print(packet)  # GUI in the future.

    terminate_connection(packet)


def start_sniffing(blacklist: list[str]) -> None:
    """Start sniffing the network and process each packet."""
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
