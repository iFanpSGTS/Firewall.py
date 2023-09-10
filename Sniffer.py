import pydivert
import Filter
from threading import Thread


class sniffer(Thread):
    """Sniffer function"""

    running = True

    def __init__(self, interfacelink, cmdlink):
        Thread.__init__(self)
        self.__win = pydivert.WinDivert()
        self.__cmdlink = cmdlink
        self.__interfacelink = interfacelink

    def decorticate_packet(self):
        packets = self.__win.recv()

        return packets

    def decorticate_ipv4(self, packets):
        ipv4_header = packets.ipv4

        if ipv4_header == None:
            return 0, 0, 0, 0, 0

        else:
            destination = ipv4_header.dst_addr
            source = ipv4_header.src_addr
            ttl = ipv4_header.ttl
            header_length = ipv4_header.header_len
            protocol = ipv4_header.protocol

            return destination, source, ttl, header_length, protocol

    def decorticate_tcp_stack(self, packets):
        tcp = packets.tcp

        if tcp == None:
            return 0, 0, 0

        else:
            dst_port = tcp.dst_port
            src_port = tcp.src_port
            header_length = tcp.header_len

            return dst_port, src_port, header_length

    def decorticate_udp_stack(self, packets):
        udp = packets.udp

        if udp == None:
            return 0, 0, 0, 0

        else:
            src_port = udp.src_port
            dest_port = udp.dst_port
            payload = udp.payload
            payload_len = udp.payload_len
            checksum = udp.cksum

            return src_port, dest_port, checksum, payload_len

    def decorticate_icmpv4(self, packets):
        icmp = packets.icmpv4

        if icmp == None:
            return 0, 0, 0

        else:
            icmp_type = icmp.type
            icmp_code = icmp.code
            payload = icmp.payload[:10]

            return icmp_type, icmp_code, payload

    def run(self):
        self.__win.open()
        while self.running:
            packs_interface = {}
            try:
                packets = self.decorticate_packet()

                icmp_type, icmp_code, payload = self.decorticate_icmpv4(packets)  # icmp

                if packets.is_inbound:
                    tcp_dst_port, tcp_src_port, header_length = self.decorticate_tcp_stack(packets)  # tcp
                    udp_src_port, udp_dst_port, udp_checksum, payload_len = self.decorticate_udp_stack(packets)  # udp
                    # print(payload_len)
                    ipv4_destination, ipv4_source, ipv4_ttl, ipv4_header_length, ipv4_header_protocol = self.decorticate_ipv4(packets)  # ipv4

                    packs_interface = {"ipsrc": ipv4_source, "ipdest": ipv4_destination}

                    # -- TRAITEMENT TCP
                    if tcp_dst_port != 0 or tcp_src_port != 0:
                        packs_interface["protocol"] = "TCP"
                        packs_interface["portsrc"] = str(tcp_src_port)
                        packs_interface["portdest"] = str(tcp_dst_port)

                    # -- TRAITEMENT UDP
                    elif udp_src_port != 0 or udp_dst_port != 0:
                        packs_interface["protocol"] = "UDP"
                        packs_interface["portsrc"] = str(udp_src_port)
                        packs_interface["portdest"] = str(udp_dst_port)

                    elif icmp_type != 0 or icmp_type != 0 or payload != 0:
                        packs_interface["protocol"] = "ICMP"

                    if packs_interface["ipsrc"] != 0 and packs_interface["ipdest"] != 0:
                        self.__cmdlink.append(packs_interface)
                        self.__interfacelink.append(packs_interface)

                if Filter.firewall(packs_interface):  # Accept packets if restrictions doesn't correspond
                    self.__win.send(packets)

            except AttributeError as ex:
                pass
            except OSError as err:
                print(err.args)
        self.__win.close()
