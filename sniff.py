import socket
import struct
import sys
import os
import datetime
import sqlite3


# Функция сканирования доступных интерфейсов
def scan_interfaces():
    interfaces = []
    with os.popen('ip link show') as f:
        for line in f:
            if 'status: active' in line:
                interface = line.split()[1].strip(':')
                interfaces.append(interface)
    return interfaces

# Функция выбора интерфейса
def select_interface(interfaces):
    print("Доступные сетевые интерфейсы:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface}")
    selected_interface = None
    while selected_interface is None:
        try:
            selected_index = int(input("Введите номер интерфейса, на котором нужно выполнить сниффинг: ")) - 1
            selected_interface = interfaces[selected_index]
        except (ValueError, IndexError):
            print("Некорректный ввод. Попробуйте еще раз.")
    return selected_interface

# Функция сниффинга на выбранном интерфейсе
def sniff(interface):
    # Создание RAW сокета для сниффинга
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as e:
        print("Ошибка создания сокета: ", e)
        sys.exit()

    # Привязка сокета к интерфейсу
    sniffer.bind((interface, 0))

    # Сниффинг пакетов
    while True:
        raw_packet, addr = sniffer.recvfrom(65535)
        time_for_table = "TIME OF RECEIPT: " + datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
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

#        elif eth_header['protocol'] == 0x86DD:
#            # IPv6-пакет
#            ipv6_header = decode_ipv6_packet(raw_packet[14:])
 #           if ipv6_header['next_header'] == 58:
 #               # ICMPv6-пакет
 #               icmpv6_header = decode_icmpv6_packet(ipv6_header['data'])
 #               print(icmpv6_header)
 #           elif ipv6_header['next_header'] == 6:
 #               # TCP-пакет
 #               tcp_header = decode_tcp_packet(ipv6_header['data'])
 #               print(tcp_header)
  #          elif ipv6_header['next_header'] == 17:
  #              # UDP-пакет
  #              udp_header = decode_udp_packet(ipv6_header['data'])
  #              print(udp_header)
  #              if udp_header['dst_port'] == 80 or udp_header['src_port'] == 80:
   #                 # HTTP-пакет
   #                 http_header = decode_http_packet(udp_header['data'])
   #                 print(http_header)
   #             elif udp_header['dst_port'] == 443 or udp_header['src_port'] == 443:
   #                 # HTTPS-пакет
    #                https_header = decode_https_packet(udp_header['data'])
    #                print(https_header)
     #       else:
     #           print(ipv6_header)
        
        else:
            print(f"Неизвестный протокол: {eth_header['protocol']}")
            her = f"Неизвестный протокол: {eth_header['protocol']}"
            data_for_table += str(her)
 
        if data_for_table:
            packet = "DECODING PACKET: " + data_for_table
            raw_packet_plus = 'RAW PACKET: ' + str(raw_packet)
            insert_packet(db_conn, table_name, time_for_table, packet, raw_packet_plus)

def decode_ethernet_header(raw_packet):
    ethernet_header = {}
    # Unpack the Ethernet frame (mac src/dst, ethertype)
    ethernet_header_data = struct.unpack('!6s6sH', raw_packet[:14])
    ethernet_header['source_mac'] = ethernet_header_data[0].hex()
    ethernet_header['destination_mac'] = ethernet_header_data[1].hex()
    ethernet_header['protocol'] = ethernet_header_data[2]
    return ethernet_header

def decode_ip_packet(packet):
    ip_header = {}

    # Разбор заголовка IP-пакета
    header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    ip_header['version'] = (header[0] & 0xf0) >> 4
    ip_header['header_length'] = (header[0] & 0x0f) * 4
    ip_header['tos'] = header[1]
    ip_header['total_length'] = header[2]
    ip_header['id'] = header[3]
    ip_header['flags'] = (header[4] & 0xe000) >> 13
    ip_header['fragment_offset'] = header[4] & 0x1fff
    ip_header['ttl'] = header[5]
    ip_header['protocol'] = header[6]
    ip_header['checksum'] = header[7]
    ip_header['src_address'] = socket.inet_ntoa(header[8])
    ip_header['dst_address'] = socket.inet_ntoa(header[9])
    ip_header['data'] = packet[ip_header['header_length']:]

    return ip_header

def decode_icmp_packet(data):
    icmp_header = {}
    # Разбор заголовка ICMP
    icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", data[:4])
    icmp_header['type'] = icmp_type
    icmp_header['code'] = icmp_code
    icmp_header['checksum'] = icmp_checksum
    # Разбор данных ICMP
    icmp_data = data[4:]
    if icmp_type == 0 or icmp_type == 8:
        # Echo-reply или Echo-request
        icmp_id, icmp_seq = struct.unpack("!HH", icmp_data[:4])
        icmp_header['id'] = icmp_id
        icmp_header['seq'] = icmp_seq
        icmp_header['data'] = icmp_data[4:]
    elif icmp_type == 3:
        # Destination-unreachable
        icmp_header['unreachable_data'] = icmp_data
    elif icmp_type == 11:
        # Time-exceeded
        icmp_header['time_exceeded_data'] = icmp_data
    else:
        # Неизвестный тип ICMP
        icmp_header['unknown_data'] = icmp_data
    return icmp_header

def decode_tcp_packet(ip_data):
    # Разбираем заголовок TCP
    tcp_header = struct.unpack('!HHLLBBHHH', ip_data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq_num = tcp_header[2]
    ack_num = tcp_header[3]
    data_offset = tcp_header[4] >> 4
    reserved = (tcp_header[4] >> 1) & 0x7
    flags = tcp_header[5]
    window = tcp_header[6]
    checksum = tcp_header[7]
    urgent_pointer = tcp_header[8]

    # Создаем словарь для хранения данных о пакете TCP
    tcp_packet = {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq_num': seq_num,
        'ack_num': ack_num,
        'data_offset': data_offset,
        'reserved': reserved,
        'flags': flags,
        'window': window,
        'checksum': checksum,
        'urgent_pointer': urgent_pointer,
        'data': ip_data[4 * data_offset:]
    }

    return tcp_packet

def decode_udp_packet(data):
    udp_header = {}

    # Разбор заголовка UDP-пакета
    header = struct.unpack('!HHHH', data[:8])
    udp_header['src_port'] = header[0]
    udp_header['dst_port'] = header[1]
    udp_header['length'] = header[2]
    udp_header['checksum'] = header[3]
    udp_header['data'] = data[8:]

    return udp_header

def decode_http_packet(data):
    if not data or b'\r\n' not in data:
        return {'error': 'no data or invalid data format'}

    # Разбиваем пакет на строки
    lines = data.split(b'\r\n')
    
    # Разбираем первую строку (request line)
    request_line = lines[0].decode('iso-8859-1')
    method, path, version = request_line.split(' ')
    
    # Разбираем заголовки (headers)
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        key, value = line.decode('iso-8859-1').split(': ')
        headers[key] = value
    
    # Разбираем тело сообщения (message body)
    body = None
    if b'\r\n\r\n' in data:
        body = data.split(b'\r\n\r\n')[1]
    
    # Возвращаем результат в виде http_header
    http_header = {
        'method': method,
        'path': path,
        'version': version,
        'headers': headers,
        'body': body
    }
    
    return http_header

def decode_https_packet(data):
    if len(data) < 5:
        return {'error': 'Packet is too short to contain a valid SSL header.'}
    
    https_header = {}
    https_header['content_type'] = data[0]
    https_header['ssl_version'] = (data[1], data[2])
    https_header['length'] = int.from_bytes(data[3:5], byteorder='big')
    
    # Check if the packet is long enough to contain the SSL header and the data
    if len(data) < https_header['length'] + 5:
        return {'error': 'Packet is too short to contain the SSL header and data.'}
    
    https_header['data'] = data[5:https_header['length']+5]
    
    return https_header

def create_table(db_conn):
    cursor = db_conn.cursor()
    current_time = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    table_name = f"SNIFF_{current_time}"
    cursor.execute(f"CREATE TABLE IF NOT EXISTS {table_name} (time TEXT, packet TEXT, raw_packet TEXT)")
    return table_name

def insert_packet(db_conn, table_name, time, packet, raw_packet):
    cursor = db_conn.cursor()
    cursor.execute(f"INSERT INTO {table_name} VALUES (?, ?, ?)", (time, packet, raw_packet))
    db_conn.commit()

if __name__ == '__main__':
    db_conn = sqlite3.connect("packets.db")
    table_name = create_table(db_conn)
    interfaces = scan_interfaces()
    if not interfaces:
        print("Нет доступных сетевых интерфейсов.")
        sys.exit()
    selected_interface = select_interface(interfaces)
    print(f"Запуск сниффинга на интерфейсе {selected_interface}...")
    sniff(selected_interface)
    db_conn.close()
