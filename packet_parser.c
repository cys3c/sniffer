#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>

int global_p_number = 0;
int udp_packets = 0;
int tcp_packets = 0;
int other_packets = 0;

void packetparser(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    // Parsing the ETHERNET header
    struct ether_header *e_header;
    e_header = (struct ether_header*) packet;
    u_short p_type = e_header->ether_type;
    char* buffer;
    char p_src[100];
    char p_des[100];

    buffer = ether_ntoa((const struct ether_addr*)&e_header->ether_shost);
    strcpy(p_src, buffer);
    buffer = ether_ntoa((const struct ether_addr*)&e_header->ether_dhost);
    strcpy(p_des, buffer);

    // Printing source and destination MAC address
    printf("\nPacket #%d\n", global_p_number);
    printf("Source MAC Address: %s\n",p_src);
    printf("Destination MAC Address: %s\n",p_des);

    // Checking if IP packet
    if (ntohs(p_type) == ETHERTYPE_IP) {
        // Parsing the IP header
        const struct ip* ip;
        ip = (struct ip*)(packet + sizeof(struct ether_header));
        char ip_src[100];
        char ip_des[100];
        buffer = inet_ntoa(ip->ip_src);
        strcpy(ip_src, buffer);
        buffer = inet_ntoa(ip->ip_dst);
        strcpy(ip_des, buffer);
        u_char ip_protocol = ip->ip_p;

        // Printing source and destination IP address
        printf("IP Source Address: %s\n", ip_src);
        printf("IP Destination Address: %s\n", ip_des);

        // Printing protocol information
        if (ip_protocol == IPPROTO_TCP) {
          // Printing destination and source ports and type
          const struct tcphdr* tcp;
          tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
          uint16_t tcp_sport = ntohs(tcp->th_sport);
          uint16_t tcp_dport = ntohs(tcp->th_dport);
          u_short tcp_chksum = ntohs(tcp->th_sum);
          printf("Packet type: TCP\n");
          printf("Source Port: %d\n", tcp_sport);
          printf("Destination Port: %d\n", tcp_dport);
          // printf("Checksum: %hu\n", tcp_chksum);
          printf("Checksum: 0x%x\n", tcp_chksum);

          // Calculating payload size and printing it
          int ip_total_bytes = ntohs(ip->ip_len);
          int ip_hdr_bytes = ip->ip_hl*32/8;
          int tcp_hdr_bytes = tcp->th_off*32/8;
          int payload_bytes = ip_total_bytes - ip_hdr_bytes - tcp_hdr_bytes;
          printf("Payload size: %d\n", payload_bytes);

          // Increasing number of TCP packets received
          tcp_packets++;
        } else if (ip_protocol == IPPROTO_UDP) {
          // Printing destination and source ports and type
          const struct udphdr* udp;
          udp = (struct udphdr*)(packet + sizeof(struct ether_header)+ sizeof(struct ip));
          uint16_t udp_sport = ntohs(udp->uh_sport);
          uint16_t udp_dport = ntohs(udp->uh_dport);
          printf("Packet type: UDP\n");
          printf("Source Port: %hu\n", udp_sport);
          printf("Destination Port: %hu\n", udp_dport);

          // Calculating payload size and printing it
          int ip_total_bytes = ntohs(ip->ip_len);
          int ip_hdr_bytes = ip->ip_hl*32/8;
          int udp_hdr_bytes = 8;
          int payload_bytes = ip_total_bytes - ip_hdr_bytes - udp_hdr_bytes;
          printf("Payload size: %d\n", payload_bytes);

          // Increasing number of UDP packets received
          udp_packets++;
        } else {
          printf("Packet type: Other\n");

          // Calculating payload size and printing it (no information on header/data breakdown within)
          int ip_total_bytes = ntohs(ip->ip_len);
          int ip_hdr_bytes = ip->ip_hl*32/8;
          int payload_bytes = ip_total_bytes - ip_hdr_bytes;
          printf("Payload size: %d\n", payload_bytes);

          // Increasing number of other packets received
          other_packets++;
        }

        // Increasing the packet global variable for the next packet
        global_p_number++;
    } else {
        printf("\nNot an IP packet.\n");
    }
}

int main(int argc, char *argv[] ) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pf;
  struct bpf_program fp;
  char filter[] = "";
  struct pcap_pkthdr h;
  const u_char *p;
  void exit();

  if(argc != 2){
    fprintf(stderr, "Usage: %s {pcap-file}\n", argv[0]);
    exit( 1 );
  }

  if((pf = pcap_open_offline( argv[1], errbuf )) == NULL){
    fprintf(stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
    exit( 1 );
  }

  if(pcap_compile(pf, &fp, filter, 0, 0 ) == -1) {
    fprintf(stderr, "BPF compile errors on %s: %s\n", filter, pcap_geterr(pf) );
    exit( 1 );
  }

  if(pcap_setfilter(pf, &fp) == -1){
    fprintf(stderr, "Can't install filter '%s': %s\n", filter, pcap_geterr(pf));
    exit( 1 );
  }

  pcap_loop(pf,-1,packetparser,NULL);

  printf("\nTotal packets received: %d\n", global_p_number);
  printf("TCP packets received: %d\n", tcp_packets);
  printf("UDP packets received: %d\n", udp_packets);
  printf("Other packets received: %d\n", other_packets);

  exit(0);
}
