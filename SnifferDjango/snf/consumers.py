import sys
from datetime import datetime
from socket import socket
from channels.generic.websocket import WebsocketConsumer
import json
import time
from .models import Packet, SniffRun, Signature, CheckedPackets
from .sniff import decode_ethernet_header, decode_ip_packet, decode_icmp_packet, decode_tcp_packet, decode_http_packet, \
    decode_https_packet, decode_udp_packet
import string
import random


class SniffConsumer(WebsocketConsumer):

    def get_random_string(self, length):
        # choose from all lowercase letter
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str

    def connect(self):
        self.interface = self.scope["url_route"]["kwargs"]["interface"]
        self.accept()
        self.sniff()

    def receive(self, text_data=None, bytes_data=None):
        print(text_data)

    def sniff(self):
        # Создание RAW сокета для сниффинга
        try:
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as e:
            print("Ошибка создания сокета: ", e)
            sys.exit()

        # Привязка сокета к интерфейсу
        sniffer.bind((self.interface, 0))

        # Сниффинг пакетов
        sniff_run = SniffRun.objects.create()
        signatures = Signature.objects.all()
        while True:
            raw_packet, addr = sniffer.recvfrom(65535)
            data_for_table = ''
            eth_header = decode_ethernet_header(raw_packet)
            if eth_header['protocol'] == 0x0800:
                # IPv4-пакет
                ip_header = decode_ip_packet(raw_packet[14:])
                print(ip_header)
                data_for_table += str(ip_header)
                if ip_header['protocol'] == 1:
                    # ICMP-пакет
                    icmp_header = decode_icmp_packet(ip_header['data'])
                    print(icmp_header)
                    data_for_table += str(icmp_header)
                elif ip_header['protocol'] == 6:
                    # TCP-пакет
                    tcp_header = decode_tcp_packet(ip_header['data'])
                    print(tcp_header)
                    data_for_table += str(tcp_header)
                    if tcp_header['dst_port'] == 80 or tcp_header['src_port'] == 80:
                        # HTTP-пакет
                        try:
                            http_header = decode_http_packet(tcp_header['data'])
                            print(http_header)
                            data_for_table += str(http_header)
                        except UnicodeDecodeError:
                            continue
                    elif tcp_header['dst_port'] == 443 or tcp_header['src_port'] == 443:
                        # HTTPS-пакет
                        https_header = decode_https_packet(tcp_header['data'])
                        print(https_header)
                        data_for_table += str(https_header)
                elif ip_header['protocol'] == 17:
                    # UDP-пакет
                    udp_header = decode_udp_packet(ip_header['data'])
                    print(udp_header)
                    data_for_table += str(udp_header)
                    if udp_header['dst_port'] == 80 or udp_header['src_port'] == 80:
                        # HTTP-пакет
                        http_header = decode_http_packet(udp_header['data'])
                        print(http_header)
                        data_for_table += str(http_header)
                    elif udp_header['dst_port'] == 443 or udp_header['src_port'] == 443:
                        # HTTPS-пакет
                        https_header = decode_https_packet(udp_header['data'])
                        print(https_header)
                        data_for_table += str(https_header)
                else:
                    print(ip_header)
                    data_for_table += str(ip_header)

            #        elif eth_header['protocol'] == 0x0806:
            #            # ARP-пакет
            #            arp_header = decode_arp_packet(raw_packet[14:])
            #            print(arp_header)

            else:
                print(f"Неизвестный протокол: {eth_header['protocol']}")
                her = f"Неизвестный протокол: {eth_header['protocol']}"
                data_for_table += str(her)

            if data_for_table:
                packet = "DECODING PACKET: " + data_for_table
                raw_packet_plus = 'RAW PACKET: ' + str(raw_packet)
                data = Packet.objects.create(start_sniffer=sniff_run, packet=packet, raw_packet=raw_packet_plus)
                self.send(json.dumps(
                    {"type": "packet", "time": data.date.strftime("%m/%d/%Y, %H:%M:%S"), "packet": data.packet,
                     "raw_packet": data.raw_packet}))
                for signature in signatures:
                    if signature.signature in raw_packet or signature.signature in packet:
                        CheckedPackets.objects.create(packet=data, signature=signature)
                        self.send(json.dumps(
                            {"type": "sign", "name": signature.name}))
