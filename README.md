# Sniffer (Packet Trace Parser)

## General
Supply any pcap file, produced by tcpdump, that contains a packet trace for the program to use as input: ./parser [pcap_file]

## Packet parser
Parses each packet in the file provided on standard input and displays basic header information on standard output:
* Packet type (TCP, UDP, other)
* Source and destination MAC address 
* Source and destination IP address (if IP packet)
* Source and destination ports (if TCP or UDP)
* Checksum (if TCP) and payload size
Prints the total number of packets processed and the numbers
of TCP, UDP and non-TCP/UDP packets.


## TCP parser
Program records each TCP connection into into files that represent the data sent and received on each side of the connection, ignoring packets that aren't TCP.

For each connection, we create three files in the current directory:
1. Metadata (e.g., "1.meta"): basic information about the connection, including:
* Initiator and responder IP address
* Initiator and responder port number
* Number of packets sent, in each direction
* Number of bytes sent, in each direction
* Number of duplicate packets detected, in each direction
* Whether the connection was closed before EOF was reached by checking 4-way handshake

2. Data from initiator (e.g., "1.initiator"): all the TCP payload data in the connection sent from the initiator to the responder, but only if the responder has acknowledged it and it is not a duplicate. Data in each subsequent packet in the connection should be concatenated to the end of the file as it is acknowledged.

3. Data from responder (e.g., "1.responder"): all corresponding data sent from responder to initiator.

## Email parser
Records the SMTP email traffic in the packet trace via TCP servers.
For each email message sent to an SMTP server, creates a file (e.g., "1.mail") that contains:
* The IP addresses of the sender and receiver
* Whether the message was accepted or rejected by the server.
* The message headers and body (if any).


## Cookie parser
Detects and parses cookies in http traffic. Stores all the name/value pairs in one file for each connection (e.g., "1.cookie")