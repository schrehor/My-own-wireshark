from scapy.all import *
from collections import Counter
import struct


def load_pcap(name):
    try:
        file = rdpcap("pcap/" + name + ".pcap")
        return file
    except FileNotFoundError:
        print("Subor neexistuje")
        return None


def get_mac_format(byte_mac):
    format_mac_byte = map('{:02x}'.format, byte_mac)
    return ':'.join(format_mac_byte)


def get_mac_addr(packet):
    dst_mac, src_mac = struct.unpack("!6s6s", packet[:12])
    dst_mac_str = "Cieľová MAC adresa: " + get_mac_format(dst_mac)
    src_mac_str = "Zdrojová MAC adresa: " + get_mac_format(src_mac)

    return src_mac_str, dst_mac_str


def get_protocol(file_name, prot_num, offset):
    file = open(file_name)

    for line in file:
        ether_int = line[:offset]
        ether_name = line[offset + 1:].rstrip("\n")
        if int(ether_int) == prot_num:
            file.close()
            return ether_name
    file.close()
    return "Neznámy typ (" + str(prot_num) + ")"


def get_type_ieee(packet):
    pac_type = struct.unpack("!B", packet[14:15])

    if pac_type[0] == 170:
        snap_type = struct.unpack("!H", packet[20:22])
        return "IEEE 802.3 LLC + SNAP", get_protocol("compare files/ethertype.txt", snap_type[0], 5)
    elif pac_type[0] == 255:
        return "IEEE 802.3 – Raw", "IPX\n"
    else:
        return "IEEE 802.3 LLC", get_protocol("compare files/sap_protocol.txt", pac_type[0], 3)


def get_packet_type(packet):
    pac_type = struct.unpack("!H", packet[12:14])
    ether_type = open("compare files/ethertype.txt")

    for lines in ether_type:
        if str(pac_type[0]) in lines:
            ether_type.close()
            return "Ethernet II", get_protocol("compare files/ethertype.txt", pac_type[0], 5)
    return get_type_ieee(packet)


def get_packet_length(packet):
    api_len = "Dĺžka rámca poskytnutá pcap API: " + str(len(packet))

    if len(packet) < 60:
        med_len = "Dĺžka rámca prenášaného po médiu: " + str(64)
        return api_len, med_len
    else:
        med_len = "Dĺžka rámca prenášaného po médiu: " + str(len(packet) + 4)
        return api_len, med_len


def print_packet(packet):
    for i in range(len(packet)):
        if i % 16 == 0:
            print()
        print('{:02x}'.format(packet[i]), end=" ")
    print("\n")


def get_ipv4_info(packet):
    ihl, protocol, src_ip, dst_ip = struct.unpack("!1B 8x 1B 2x 4s 4s", packet[14:34])
    src_ip = '.'.join(map(str, src_ip))
    dst_ip = '.'.join(map(str, dst_ip))
    ihl -= 64
    return src_ip, dst_ip, ihl, protocol


def print_ip_info(ip_list):
    ip_list = Counter(ip_list)

    print("Zoznam IP adries všetkých prijímajúcich uzlov")
    for key, value in ip_list.items():
        print(key)

    key = max(ip_list, key=ip_list.get)
    print("\nNajviac packetov prijala IP adresa ", key, " s ", ip_list[key], " packetmi")


def protocol_read(packet, protocol, ihl):
    list = []
    if protocol == 1:
        type = struct.unpack("!1B", packet[14 + ihl * 4:15 + ihl * 4])
        list.append("Code: " + str(type[0]) + " " + get_protocol("compare files/icmp_type.txt", type[0], 2))
    elif protocol == 6:
        type = struct.unpack("!1H1H", packet[14 + ihl * 4:18 + ihl * 4])
        list.append("Src Port: " + str(type[0]) + " " + get_protocol("compare files/tcp_ports.txt", type[0], 3))
        list.append("Dst Port: " + str(type[1]) + " " + get_protocol("compare files/tcp_ports.txt", type[1], 3))
    elif protocol == 17:
        type = struct.unpack("!1H1H", packet[14 + ihl * 4:18 + ihl * 4])
        list.append("Src Port: " + str(type[0]) + " " + get_protocol("compare files/udp_ports.txt", type[0], 3))
        list.append("Dst Port: " + str(type[1]) + " " + get_protocol("compare files/udp_ports.txt", type[1], 3))
    return list


def protocol_read_plain(packet, protocol, ihl):
    list = []
    if protocol == 1:
        type = struct.unpack("!1B", packet[14 + ihl * 4:15 + ihl * 4])
        list.append(type[0])
    elif protocol == 6:
        type = struct.unpack("!1H1H", packet[14 + ihl * 4:18 + ihl * 4])
        list.append(type[0])
        list.append(type[1])
    elif protocol == 17:
        type = struct.unpack("!1H1H", packet[14 + ihl * 4:18 + ihl * 4])
        list.append(type[0])
        list.append(type[1])
    return list


def protocol_read_text(packet, protocol, ihl):
    list = []
    if protocol == 1:
        type = struct.unpack("!1B", packet[14 + ihl * 4:15 + ihl * 4])
        list.append(get_protocol("compare files/icmp_type.txt", type[0], 2))
    elif protocol == 6:
        type = struct.unpack("!1H1H", packet[14 + ihl * 4:18 + ihl * 4])
        list.append(get_protocol("compare files/tcp_ports.txt", type[0], 3))
        list.append(get_protocol("compare files/tcp_ports.txt", type[1], 3))
    elif protocol == 17:
        type = struct.unpack("!1H1H", packet[14 + ihl * 4:18 + ihl * 4])
        list.append(get_protocol("compare files/udp_ports.txt", type[0], 3))
        list.append(get_protocol("compare files/udp_ports.txt", type[1], 3))
    return list


def print_packet_info(i, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot):
    print("Rámec číslo:", i + 1)
    print(api_len)
    print(medium_len)
    print(src_mac)
    print(dst_mac)
    print(pack_type)
    print(pack_prot)


def print_packets(pcap_name):
    pcap_file = load_pcap(pcap_name)
    if pcap_file is None:
        return 1

    file = open("result.txt", "w")
    stdout_orig = sys.stdout
    sys.stdout = file
    ip_save = []

    for i in range(len(pcap_file)):
        api_len, medium_len = get_packet_length(pcap_file[i])
        src_mac, dst_mac = get_mac_addr(bytes(pcap_file[i]))
        pack_type, pack_prot = get_packet_type(bytes(pcap_file[i]))

        if pack_prot == "IPv4":
            src_ip, dst_ip, ihl, protocol = get_ipv4_info(bytes(pcap_file[i]))
            ip_save.append(dst_ip)
            transport_prot = get_protocol("compare files/ip_protocol.txt", protocol, 2)
            application_prot = protocol_read(bytes(pcap_file[i]), protocol, ihl)

            print_packet_info(i, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot)
            print_piv4_info(application_prot, dst_ip, src_ip, transport_prot)
        else:
            print_packet_info(i, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot)
        print_packet(bytes(pcap_file[i]))

    print_ip_info(ip_save)

    sys.stdout = stdout_orig
    file.close()


def print_piv4_info(application_prot, dst_ip, src_ip, transport_prot):
    print("Zdrojová IP adresa: " + src_ip)
    print("Cieľová IP adresa: " + dst_ip)
    print(transport_prot)
    if application_prot is not None:
        print(*application_prot, sep="\n")


def print_menu():
    print("p - Na vypis pcap suboru \n"
          "f - Na vytvorenie filtra urcitej komunikacie \n"
          "m - Na vypis menu \n"
          "x - Na skoncenie aplikacie")
    return input("Zadajte co chcete urobit: ")


def print_arp_comm(list):
    for item in list:
        item[1] = "Rámec číslo: " + str(item[1])
        item[8] = "ARP operator: " + str(item[8]) + " " + str(
            get_protocol("compare files/arp_operation.txt", item[8], 1))
        item[9] = "Target IP: " + str(item[9])
        item[10] = "Source IP: " + str(item[10])
        item[11] = "Target Mac: " + str(item[11])
        item[12] = "Source Mac: " + str(item[12])
        if len(item) == 27:
            item[0] = "Komunikícia číslo: " + str(item[0]) + " (Úplná)"
            item[14] = "Rámec číslo: " + str(item[14])
            item[21] = "ARP operator: " + str(item[21]) + " " + str(
                get_protocol("compare files/arp_operation.txt", item[21], 1))
            item[22] = "Target IP: " + str(item[22])
            item[23] = "Source IP: " + str(item[23])
            item[24] = "Target Mac: " + str(item[24])
            item[25] = "Source Mac: " + str(item[25])
        else:
            item[0] = "Komunikícia číslo: " + str(item[0]) + " (Neúplná)"

    return list


def check_arp_comm(filter_list, counter):
    index = len(filter_list) - 2

    if filter_list[index + 1][9] == filter_list[index][10] and filter_list[index + 1][10] == filter_list[index][9]:
        filter_list[index].extend(filter_list[index + 1][1:])
        del filter_list[index + 1]
        counter -= 1

    return filter_list, counter


def analyze_arp(filter_list, packet, counter):
    oper, src_mac, src_ip, dst_mac, dst_ip = struct.unpack("!1H 6s 4s 6s 4s", packet[20:42])
    src_mac = get_mac_format(src_mac)
    dst_mac = get_mac_format(dst_mac)
    src_ip = '.'.join(map(str, src_ip))
    dst_ip = '.'.join(map(str, dst_ip))

    packet_hex = filter_list[len(filter_list) - 1][8]
    del filter_list[len(filter_list) - 1][8]
    filter_list[len(filter_list) - 1].extend([oper, dst_ip, src_ip, dst_mac, src_mac, packet_hex])

    if oper == 2:
        filter_list, counter = check_arp_comm(filter_list, counter)

    return filter_list, counter


def print_filter_value(filter_list):
    new_list = filter_list
    if len(filter_list) > 20:
        new_list = filter_list[:10]
        new_list.extend(filter_list[-11:])

    for list in new_list:
        for line in list:
            if type(line) is bytes:
                print_packet(line)
            else:
                print(line)


def find_icmp_comm(list):
    for i in range(len(list)):
        if list[len(list) - i - 1][11] == 8:
            return len(list) - i - 1
    return None



def get_icmp_comm(list, counter):
    if list[len(list) - 1][11] == 0:
        index = find_icmp_comm(list)
        if index is not None and list[index][11] == 8 and list[index][8] == list[len(list) - 1][9] and \
                list[index][9] == list[len(list) - 1][8]:
            list[index].extend(list[len(list) - 1])
            del list[len(list) - 1]
            counter -= 1

    return list, counter


def print_icmp_comm(filter_list):
    for item in filter_list:
        item[1] = "Rámec číslo: " + str(item[1])
        item[8] = "Destination IP: " + str(item[9])
        item[9] = "Source IP: " + str(item[9])
        item[10] = get_protocol("compare files/ip_protocol.txt", item[10], 2)
        item[11] = str(item[11]) + " " + get_protocol("compare files/icmp_type.txt", item[11], 2)
        if len(item) == 26:
            item[0] = "Komunikícia číslo: " + str(item[0]) + " (Úplná)"
            item[14] = "Rámec číslo:" + str(item[14])
            item[21] = "Destination IP: " + str(item[21])
            item[22] = "Source IP: " + str(item[22])
            item[23] = get_protocol("compare files/ip_protocol.txt", item[23], 2)
            item[24] = str(item[24]) + " " + get_protocol("compare files/icmp_type.txt", item[24], 2)
            item.pop(13)
        else:
            item[0] = "Komunikícia číslo: " + str(item[0]) + " (Neúplná)"

    return filter_list


def print_ready(filter_list):
    for item in filter_list:
        item[0] = "Rámec číslo: " + str(item[0])
        item[7] = "Source IP: " + str(item[7])
        item[8] = "Destination IP: " + str(item[8])
        item[9] = get_protocol("compare files/ip_protocol.txt", item[9], 2)
        item[10] = str(item[10]) + " " + get_protocol("compare files/" + item[9].lower() + "_ports.txt", item[10], 3)
        item[11] = str(item[11]) + " " + get_protocol("compare files/" + item[9].lower() + "_ports.txt", item[11], 3)

    return filter_list


def copy_list(list):
    new_list = list[:]
    return new_list


def get_flag(established, ihl, memory, connection, connection_info):
    flag = struct.unpack("!1H", connection_info[len(connection_info) - 1][26 + 4 * ihl:28 + 4 * ihl])
    flag = flag[0]
    if flag == 40962 and memory == -1:
        connection.append(copy_list(connection_info))
        return 1, False, connection
    elif flag == 20484 and memory != -1 and established:
        connection.append(copy_list(connection_info))
        return 10, False, connection
    elif flag == 40978 and memory == 1:
        connection.append(copy_list(connection_info))
        return 2, False, connection
    elif memory == 2 and (flag == 32784 or flag == 32792):
        connection.append(copy_list(connection_info))
        return 0, True, connection
    elif memory == 0 and (flag == 32785 or flag == 20500):
        connection.append(copy_list(connection_info))
        return 4, True, connection
    elif flag == 32785 and memory == 4:
        connection.append(copy_list(connection_info))
        return 11, True, connection
    elif flag == 32784 and memory == 11:
        connection.append(copy_list(connection_info))
        return 10, False, connection
    elif flag == 32784 and memory == 4:
        connection.append(copy_list(connection_info))
        return 5, True, connection
    elif flag == 32785 and memory == 5:
        connection.append(copy_list(connection_info))
        return 6, True, connection
    elif flag == 32784 and memory == 6:
        connection.append(copy_list(connection_info))
        return 10, False, connection
    else:
        return memory, established, connection


def print_connection(connection, established, memory):
    start = connection[:3]
    end = connection[3:]

    print("Začiatok komunikácie")
    for item in start:
        print("Rámec číslo: " + str(item[0]))
        print(item[1])
        print(item[2])
        print(item[3])
        print(item[4])
        print(item[5])
        print(item[6])
        print("Source IP: " + str(item[8]))
        print("Destination IP: " + str(item[9]))
        print(get_protocol("compare files/ip_protocol.txt", item[9], 2))
        port = get_protocol("compare files/ip_protocol.txt", item[9], 2)
        print(str(item[10]) + " " + get_protocol("compare files/" + port.lower() + "_ports.txt", item[10], 3))
        print(str(item[11]) + " " + get_protocol("compare files/" + port.lower() + "_ports.txt", item[11], 3))
        print_packet(item[12])

    if memory == 10:
        print("Koniec komunikácie")
        for item in end:
            print("Rámec číslo: " + str(item[0]))
            print(item[1])
            print(item[2])
            print(item[3])
            print(item[4])
            print(item[5])
            print(item[6])
            print("Source IP: " + str(item[8]))
            print("Destination IP: " + str(item[9]))
            print(get_protocol("compare files/ip_protocol.txt", item[9], 2))
            port = get_protocol("compare files/ip_protocol.txt", item[9], 2)
            print(str(item[10]) + " " + get_protocol("compare files/" + port.lower() + "_ports.txt", item[10], 3))
            print(str(item[11]) + " " + get_protocol("compare files/" + port.lower() + "_ports.txt", item[11], 3))
            print_packet(item[12])
    elif established == True:
        print("Komunikácia neukončená")


def get_tftp_info(list, ports):
    ports[0] = list[len(list)-1][10]
    ports[1] = list[len(list)-1][11]

    return list, ports


def count_lldp(filter_list):
    filter_list[len(filter_list) - 1][0] = "LLDP číslo: " + str(filter_list[len(filter_list) - 1][0])
    filter_list[len(filter_list) - 1][1] = "Rámec číslo: " + str(filter_list[len(filter_list) - 1][1])

    return filter_list


def print_filter(pcap, filter):
    pcap_file = load_pcap(pcap_name)
    if pcap_file is None:
        return

    file = open("result.txt", "w")
    stdout_orig = sys.stdout
    sys.stdout = file
    filter_list = []
    connection = []
    established = False
    memory = -1
    connection_info = []
    ports = [69, 69]
    counter = 0

    for i in range(len(pcap_file)):
        api_len, medium_len = get_packet_length(pcap_file[i])
        src_mac, dst_mac = get_mac_addr(bytes(pcap_file[i]))
        pack_type, pack_prot = get_packet_type(bytes(pcap_file[i]))

        if pack_type != "Ethernet II" or pack_prot == "IPv6":
            continue
        elif pack_prot == "ARP" and filter == "ARP":
            counter += 1

            filter_list.append(
                [counter, i + 1, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot, bytes(pcap_file[i])])
            filter_list, counter = analyze_arp(filter_list, bytes(pcap_file[i]), counter)
        elif pack_prot == "LLDP" and filter == "LLDP":
            counter += 1
            filter_list.append(
                [counter, i + 1, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot, bytes(pcap_file[i])])
            filter_list = count_lldp(filter_list)
        elif pack_prot == "IPv4":
            src_ip, dst_ip, ihl, protocol = get_ipv4_info(bytes(pcap_file[i]))
            transport_prot = get_protocol("compare files/ip_protocol.txt", protocol, 2)
            application_prot = protocol_read_plain(bytes(pcap_file[i]), protocol, ihl)
            application_prot_text = protocol_read_text(bytes(pcap_file[i]), protocol, ihl)

            if not application_prot:
                continue

            if transport_prot == "ICMP":
                if filter == "ICMP":
                    counter += 1
                    filter_list.append(
                        [counter, i + 1, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot,
                         src_ip, dst_ip, protocol, application_prot[0], bytes(pcap_file[i])])
                    filter_list, counter = get_icmp_comm(filter_list, counter)
                else:
                    continue
            elif filter == "TFTP" and (application_prot[0] == ports[0] or application_prot[1] == ports[0] or
                                       application_prot[1] == ports[1] or application_prot[0] == ports[1] or
                                       application_prot[1] == 69 or application_prot[0] == 69):
                filter_list.append(
                    [i + 1, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot,
                     src_ip, dst_ip, protocol, application_prot[0], application_prot[1], bytes(pcap_file[i])])
                filter_list, ports = get_tftp_info(filter_list, ports)
            elif application_prot_text[0] == filter or application_prot_text[1] == filter:
                filter_list.append(
                    [i + 1, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot,
                     src_ip, dst_ip, protocol, application_prot[0], application_prot[1], bytes(pcap_file[i])])
            if transport_prot == "TCP":
                connection_info.clear()
                connection_info.extend([i + 1, api_len, medium_len, src_mac, dst_mac, pack_type, pack_prot,
                     src_ip, dst_ip, protocol, application_prot[0], application_prot[1], bytes(pcap_file[i])])
                memory, established, connection = get_flag(established, ihl, memory, connection, connection_info)

    if filter == "ARP":
        filter_list = print_arp_comm(filter_list)
    elif filter == "ICMP":
        filter_list = print_icmp_comm(filter_list)
    else:
        if filter != "LLDP":
            filter_list = print_ready(filter_list)
    print_filter_value(filter_list)
    if connection:
        print_connection(connection, established, memory)
    sys.stdout = stdout_orig


action = print_menu()
while action != "x":
    if action == "p":
        pcap_name = input("Zadajte nazov pcapu: ")
        if print_packets(pcap_name) == 1:
            continue
        action = "m"
    elif action == "m":
        action = print_menu()
        continue
    elif action == "f":
        print("Vsetky mozne filtre:\n"
              "HTTP\n"
              "HTTPS\n"
              "TELNET\n"
              "SSH\n"
              "FTP - riadiace\n"
              "FTP - dátove\n"
              "TFTP\n"
              "ICMP\n"
              "ARP\n"
              "LLDP\n")
        filter = input("Zadajte pozadovany filter: ")
        pcap_name = input("Zadajte nazov pcapu, na ktorom bude pouzity filter: ")
        action = "m"
        print_filter(pcap_name, filter)
    else:
        print("Zly command")
        action = "m"

    print()
