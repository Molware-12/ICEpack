import time
import subprocess
import re
import socket
import struct
import random

class IcePack:
    def __init__(self, target_ip, spoofed_ip):
        self.target_ip = target_ip
        self.spoofed_ip = spoofed_ip

    def icmp(self, payload, num_of_packets, size, type, code):
        """
Type:   Code:
0	    0	Echo Reply
3	    0	Destination Network Unreachable
3	    1	Destination Host Unreachable
3	    2	Destination Protocol Unreachable
3	    3	Destination Port Unreachable
3	    4	Fragmentation Needed and Don't Fragment was Set
3	    5	Source Route Failed
3	    6	Destination Network Unknown
3	    7	Destination Host Unknown
3	    8	Source Host Isolated
3	    9	Communication with Destination Network is Administratively Prohibited
3	    10	Communication with Destination Host is Administratively Prohibited
3	    11	Destination Network Unreachable for Type of Service
3	    12	Destination Host Unreachable for Type of Service
3	    13	Communication Administratively Prohibited
3	    14	Host Precedence Violation
3	    15	Precedence Cutoff in Effect
4	    0	Source Quench (deprecated)
5	    0	Redirect Datagram for the Network
5	    1	Redirect Datagram for the Host
5	    2	Redirect Datagram for the Type of Service and Network
5	    3	Redirect Datagram for the Type of Service and Host
8	    0	Echo Request
9	    0	Router Advertisement
9	    16	Does not route common traffic
10	    0	Router Solicitation
11	    0	Time to Live exceeded in Transit
11	    1	Fragment Reassembly Time Exceeded
12	    0	Pointer indicates the error
12	    1	Missing a required option
12	    2	Bad Length
13	    0	Timestamp Request
14	    0	Timestamp Reply
15	    0	Information Request (obsolete)
16	    0	Information Reply (obsolete)
17	    0	Address Mask Request
18	    0	Address Mask Reply
"""

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        payload = bytes(payload, "utf-8") * size
        icmp_type = type
        icmp_code = code
        icmp_seq = 1

        for _ in range(num_of_packets):
            st = time.perf_counter()
            icmp_ID = random.randint(1, 65535)
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_ID, icmp_seq)
            icmp_checksum = self.icmp_checksum(icmp_header + payload)
            icmp_packet = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_ID, icmp_seq)

            version = 4
            ihl = 5
            tos = 0
            tot_len = 20 + len(icmp_packet) + len(payload)
            id = random.randint(1, 65535)
            frag_off = 0
            ttl = 64
            protocol = socket.IPPROTO_ICMP
            check = 0
            saddr = socket.inet_aton(self.spoofed_ip)
            daddr = socket.inet_aton(self.target_ip)
            ver_ihl = (version << 4) + ihl

            ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
            ip_checksum = self.icmp_checksum(ip_header)
            ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, ip_checksum, saddr, daddr)

            packet = ip_header + icmp_packet + payload
            sock.sendto(packet, (self.target_ip, 0))
            icmp_seq += 1
            fn = time.perf_counter()
        print(f"Packets sent. Elapsed time: {fn - st}s")
    
    def icmp_checksum(self, packet):
        chksum = 0
        countTo = (len(packet) // 2) * 2
        count = 0
        
        while count < countTo:
            packet_val = packet[count + 1] * 256 + packet[count]
            chksum = chksum + packet_val
            chksum = chksum & 0xffffffff  # Ensure checksum fits within 32 bits
            count = count + 2

        if countTo < len(packet):
            chksum = chksum + packet[len(packet) - 1]
            chksum = chksum & 0xffffffff  # Ensure checksum fits within 32 bits

        chksum = (chksum >> 16) + (chksum & 0xffff)
        chksum = chksum + (chksum >> 16)
        res = ~chksum
        res = res & 0xffff
        res = res >> 8 | (res << 8 & 0xff00)
        
        return res

    def tcp(self, payload, num_of_packets, size, flag: int):
        """
        flag (int): flag should be a integer that indicates what type of tcp packet it is. The types are listed below:

        CWR (Congestion Window Reduced): Bit 7 (128)
        ECE (ECN-Echo): Bit 6 (64)
        URG (Urgent): Bit 5 (32)
        ACK (Acknowledgment): Bit 4 (16)
        PSH (Push): Bit 3 (8)
        RST (Reset): Bit 2 (4)
        SYN (Synchronize): Bit 1 (2)
        FIN (Finish): Bit 0 (1)

        """
        s_ip = socket.gethostbyname(socket.gethostname())  # Replace with the source IP address
        tcp_dest_port = 80  # Example destination port (replace with your desired port)
        payload = bytes(payload, "utf-8") * size

        tcp_source_port = random.randint(1024, 65535)  # Random source port
        tcp_seq = random.randint(0, 4294967295)  # Random sequence number
        tcp_ack = 0  # Acknowledgment number
        tcp_data_offset = 5  # Data offset (header length)
        tcp_flags = flag #TCP 
        tcp_window_size = socket.htons(64240)  # Window size
        tcp_checksum = 0  # Checksum (to be calculated later)
        tcp_urgent_pointer = 0  # Urgent pointer

        for _ in range(num_of_packets):
            pseudo_header = struct.pack('!4s4sBBH',
                                        socket.inet_aton(s_ip),
                                        socket.inet_aton(self.target_ip),
                                        0,
                                        socket.IPPROTO_TCP,
                                        800)  # Length of TCP header + data (20 bytes)

            tcp_header = struct.pack('!HHLLBBHHH',
                                    tcp_source_port,
                                    tcp_dest_port,
                                    tcp_seq,
                                    tcp_ack,
                                    (tcp_data_offset << 4),
                                    tcp_flags,
                                    tcp_window_size,
                                    tcp_checksum,
                                    tcp_urgent_pointer
                                    )

            # Calculate the TCP checksum
            tcp_checksum = self.tcp_checksum(pseudo_header + tcp_header)

            # Pack the TCP header with the correct checksum
            tcp_header = struct.pack('!HHLLBBHHH',
                            tcp_source_port,
                            tcp_dest_port,
                            tcp_seq,
                            tcp_ack,
                            (tcp_data_offset << 4) | (tcp_flags >> 2),  # Data offset and reserved bits
                            tcp_flags,
                            tcp_window_size,
                            tcp_checksum,
                            tcp_urgent_pointer)

    # Combine the TCP header and the payload
            packet = tcp_header + payload

            # Send the TCP SYN packet to the target IP
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.sendto(packet, (self.target_ip, tcp_dest_port))
                print(f"Sent TCP packet {tcp_seq}.")
                tcp_seq += 1  # Increment sequence number for each packet
            except OSError as e:
                print(f"Error sending packet: {e}")

    def tcp_checksum(self, tcp_header):
        source_ip = socket.gethostbyname(socket.gethostname())  # Example source IP address (replace with actual source IP)
        pseudo_header = struct.pack('!4s4sBBH',
                                    socket.inet_aton(source_ip),
                                    socket.inet_aton(self.target_ip),
                                    0,
                                    socket.IPPROTO_TCP,
                                    len(tcp_header))

        packet = pseudo_header + tcp_header

        # Calculate the checksum using one's complement arithmetic
        checksum = 0
        for i in range(0, len(packet), 2):
            checksum += (packet[i] << 8) + packet[i+1]
            if checksum > 0xFFFF:  # If the sum overflows beyond 16 bits, add the carry
                checksum = (checksum & 0xFFFF) + 1

        # Take the one's complement of the final sum
        checksum = ~checksum & 0xFFFF

        return checksum

    def udp(self, payload, num_of_packets, size, s_port, d_port):
        st = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        payload = bytes(payload, "utf-8") * size

        s_port = s_port
        d_port = d_port

        udp_len = 8
        udp_checksum = self.udp_checksum(s_port, d_port, udp_len, payload)
        for _ in range(num_of_packets):
            udp_header = struct.pack('!HHHH', s_port, d_port, udp_len, udp_checksum)
            udp_packet = udp_header + payload

            version = 4
            ihl = 5
            tos = 0
            tot_len = 20 + len(udp_packet) + len(payload)
            id = random.randint(1, 65535)
            frag_off = 0
            ttl = 64
            protocol = socket.IPPROTO_UDP
            check = 0
            saddr = socket.inet_aton(self.spoofed_ip)
            daddr = socket.inet_aton(self.target_ip)
            ver_ihl = (version << 4) + ihl

            ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
            ip_checksum = 0
            ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl, tos, tot_len, id, frag_off, ttl, protocol, ip_checksum, saddr, daddr)

            packet = ip_header + udp_packet
            sock.sendto(packet, (self.target_ip, 5))
            fn = time.perf_counter()
        print(f"Packets sent. Elapsed time: {fn - st}s")

    def udp_checksum(self, source_port, dest_port, udp_length, payload):
        # Create pseudo header
        pseudo_header = struct.pack('!HHHH', source_port, dest_port, udp_length, 0)
        pseudo_header_checksum = 0

        # Calculate checksum for pseudo header
        for i in range(0, len(pseudo_header), 2):
            pseudo_header_checksum += (pseudo_header[i] << 8) + pseudo_header[i+1]
            if pseudo_header_checksum > 0xFFFF:
                pseudo_header_checksum = (pseudo_header_checksum & 0xFFFF) + 1

        # Pad the payload if its length is odd
        if len(payload) % 2 == 1:
            payload += b'\0'

        # Calculate checksum for payload
        payload_checksum = 0
        for i in range(0, len(payload), 2):
            payload_checksum += (payload[i] << 8) + payload[i+1]
            if payload_checksum > 0xFFFF:
                payload_checksum = (payload_checksum & 0xFFFF) + 1

        # Calculate total checksum
        total_checksum = pseudo_header_checksum + payload_checksum
        total_checksum = (total_checksum & 0xFFFF) + (total_checksum >> 16)
        udp_checksum = ~total_checksum & 0xFFFF

        return udp_checksum
    
    def domain_ip(self, domain):
        query = subprocess.Popen(["ping", "-n", "1", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = query.communicate()
        decoded_stdout = stdout.decode('utf-8')

        pattern = r'\b(?:(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\b'
        return re.findall(pattern, decoded_stdout)[0]
    
    def dns(self, payload, num_of_packets, size, query, domain):
        """
        (query): 
        A (Address)	This record maps a domain name to an IPv4 address
        AAAA (Ipv6 Address)	This record maps a domain name to an IPv6 address
        CNAME (Canonical Name)	This record creates an alias for the domain name.
        MX (Mail Exchange)	This record specifies the mail server responsible for receiving email messages on behalf of the domain.
        NS (Name Server)	This specifies an authoritative name servers for a domain.
        PTR (Pointer)	This is used in reverse queries to map an IP to a domain name
        TXT (Text)	This is used to specify text associated with the domain
        SOA (Start of Authority)	This contains administrative information about the zone
        (domains): Refers to the name of a website. e.g. google.com."""

        # Create a raw socket to construct the packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        
        # Construct the payload
        payload = bytes(payload, "utf-8") * size
        
        # IP Header fields
        version = 4
        header_length = 5
        tos = 0
        total_length = 20 + 8 + 12 + len(domain) + 2 + len(payload)  # IP header + UDP header + DNS header + domain + type/class + payload
        identification = random.randint(0, 65535)
        flags_fragment_offset = 0
        ttl = 64
        protocol = socket.IPPROTO_UDP
        checksum = 0  # Kernel will fill the correct checksum
        source_ip = self.spoofed_ip  # Use your source IP
        dest_ip = self.domain_ip(domain)
        s_port = random.randint(1024, 65535)
        d_port = 53
        
        ip_header = struct.pack('!BBHHHBBH4s4s', 
                                (version << 4) + header_length, tos, total_length, identification, 
                                flags_fragment_offset, ttl, protocol, checksum, 
                                socket.inet_aton(source_ip), socket.inet_aton(dest_ip))
        
        # UDP Header fields
        udp_length = 8 + 12 + len(domain) + 2 + len(payload)  # UDP header + DNS header + domain + type/class + payload
        udp_checksum = self.udp_checksum(s_port, d_port, udp_length, payload)  # Optional in UDP

        udp_header = struct.pack('!HHHH', s_port, d_port, udp_length, udp_checksum)
        
        # DNS Header fields
        tID = random.randint(0, 65535)
        flags = 0x0100  # Standard query with recursion desired
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0
        CLASS = "IN"
        
        dns_header = struct.pack('!HHHHHH', tID, flags, questions, answer_rrs, authority_rrs, additional_rrs)
        
        # DNS Question fields
        qname = b''.join(struct.pack('!B', len(part)) + part.encode('utf-8') for part in domain.split('.')) + b'\x00'
        qtype = 0x001c if query == 'AAAA' else 0x0001  # AAAA for IPv6, A for IPv4
        qclass = 0x0001 if CLASS == 'IN' else 0x0001  # IN for Internet

        dns_question = qname + struct.pack('!HH', qtype, qclass)
        
        # Combine DNS Header and Question
        dns_packet = dns_header + dns_question + payload
        
        # Combine IP Header, UDP Header, and DNS Packet
        packet = ip_header + udp_header + dns_packet
        
        for _ in range(num_of_packets):
            sock.sendto(packet, (dest_ip, 0))
        print("Packets sent.")

    def mdns(self, payload, num_of_packets, size, domains: list, qtype: str):
        """
        A (Address)	This record maps a domain name to an IPv4 address
        AAAA (Ipv6 Address)	This record maps a domain name to an IPv6 address
        CNAME (Canonical Name)	This record creates an alias for the domain name.
        MX (Mail Exchange)	This record specifies the mail server responsible for receiving email messages on behalf of the domain.
        NS (Name Server)	This specifies an authoritative name servers for a domain.
        PTR (Pointer)	This is used in reverse queries to map an IP to a domain name
        TXT (Text)	This is used to specify text associated with the domain
        SOA (Start of Authority)	This contains administrative information about the zone
        """

        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Set the TTL for the multicast packet to 1
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        # Enable multicast loopback
        loopback = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loopback)

        # Bind to the mDNS port
        sock.bind(('', 5353))

        # Join the multicast group
        mreq = struct.pack('4sl', socket.inet_aton('224.0.0.251'), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Multicast address and port
        dest_ip = "224.0.0.251"
        d_port = 5353

        # Simple mDNS query payload
        tID = 0x0000  # Transaction ID
        flags = 0x0000  # Standard query, recursion desired
        questions = len(domains)  # Number of questions
        answer_rrs = 0  # Number of answer resource records
        authority_rrs = 0  # Number of authority resource records
        additional_rrs = 0  # Number of additional resource records

        dns_header = struct.pack('!HHHHHH', tID, flags, questions, answer_rrs, authority_rrs, additional_rrs)
        payload = bytes(payload, "utf-8") * size

        dns_question = b""

        for domain, qtype_str in domains.items():
            qname = b''.join(struct.pack('!B', len(part)) + part.encode('utf-8') for part in domain.split('.')) + b'\x00'
            
            # Determine the qtype
            if qtype_str == "A":
                qtype = 0x0001
            elif qtype_str == "NS":
                qtype = 0x0002
            elif qtype_str == "CNAME":
                qtype = 0x0005
            elif qtype_str == "SOA":
                qtype = 0x0006
            elif qtype_str == "PTR":
                qtype = 0x000C
            elif qtype_str == "MX":
                qtype = 0x000F
            elif qtype_str == "TXT":
                qtype = 0x0010
            elif qtype_str == "AAAA":
                qtype = 0x001C
            elif qtype_str == "SRV":
                qtype = 0x0021
            elif qtype_str == "OPT":
                qtype = 0x0029
            elif qtype_str == "ANY":
                qtype = 0x00FF
            else:
                raise ValueError("Unknown qtype: {}".format(qtype_str))

            qtype = struct.pack('!H', qtype)
            qclass = struct.pack('!H', 0x0001)  # IN class
            dns_question += qname + qtype + qclass # add each domain after each iteration

        dns_packet = dns_header + dns_question

        # Send the packet
        for _ in range(num_of_packets):
            sock.sendto(dns_packet, (dest_ip, d_port))
        print("Packets sent")
