# ICEpack

IcePack is a comprehensive Python-based simulation tool designed to craft and send various types of network packets. This simulation is an educational project aimed at demonstrating how different network protocols function by constructing and transmitting packets manually using the python struct module. Understanding packet crafting is crucial for fields such as network security, penetration testing, and network diagnostics.

ICMP Packets

icmp(self, payload, num_of_packets, size, type, code): Constructs and sends ICMP (Internet Control Message Protocol) packets. Parameters include the payload, number of packets, size, type, and code, which determine the specific ICMP message type (e.g., Echo Request, Destination Unreachable).
Checksum Calculation

icmp_checksum(self, packet): Calculates the checksum for ICMP packets, essential for packet integrity verification.
tcp_checksum(self, tcp_header): Calculates the checksum for TCP (Transmission Control Protocol) packets.
udp_checksum(self, source_port, dest_port, udp_length, payload): Calculates the checksum for UDP (User Datagram Protocol) packets.
TCP Packets

tcp(self, payload, num_of_packets, size, flag): Constructs and sends TCP packets. Parameters include payload, number of packets, size, and flag, which indicates the type of TCP packet (e.g., SYN, ACK).
UDP Packets

udp(self, payload, num_of_packets, size, s_port, d_port): Constructs and sends UDP packets. Parameters include the payload, number of packets, size, source port, and destination port.
Domain to IP Resolution

domain_ip(self, domain): Resolves a domain name to its corresponding IP address using the ping command.
DNS Packets

dns(self, payload, num_of_packets, size, query, domain): Constructs and sends DNS (Domain Name System) query packets. Parameters include payload, number of packets, size, query type (e.g., A for IPv4, AAAA for IPv6), and the domain to query.
mDNS Packets

mdns(self, payload, num_of_packets, size, domains, qtype): Constructs and sends mDNS (Multicast DNS) packets. Parameters include payload, number of packets, size, a dictionary of domains and their query types, and the query type for each domain.
Importance of Understanding Packets
Understanding packets is essential for several reasons:

Network Security: Identifying malicious packets and preventing attacks.
Troubleshooting: Diagnosing network issues and ensuring proper communication between devices.
Penetration Testing: Simulating attacks to test the security posture of a network.
Protocol Development: Creating and refining communication protocols for efficient and secure data transfer.

Also, to actually know if these packets were being sent correctly, I would advise using wireshark to do so. You can download wireshark from their website here. https://www.wireshark.org/download.html. 

Many times while running this code in a terminal it will require permissions. If you are using a Linux distribution, use the 'sudo' command along with the 'python3' command on the file. Like this: sudo python3 icepack.py 
This will work only if the permissions of the file have the +x which means 'executable'.

On a Windows system, if you run the cmd prompt as administrator and to run the command the only thing that is needed is the name of the file.