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
#include <ctype.h>

typedef struct tcp_packet{
  int global_package_number;
  int include; // to decide whether to print or not
  int duplicate; // marked as duplicate if = 1
  char ip_src[100];
  char ip_des[100];
  uint16_t tcp_sport;
  uint16_t tcp_dport;
  int tcp_FIN;
  int tcp_SYN;
  int tcp_RST;
  int tcp_PUSH;
  int tcp_ACK;
  int tcp_URG;
  long tcp_seq;
  long tcp_ack_n;
  int payload_bytes;
  u_char* payload;
} tcp_packet;

typedef struct tcp_connect{
  int number;
  char ip_src[100];
  char ip_des[100];
  uint16_t tcp_sport;
  uint16_t tcp_dport;
  int packets_init_to_resp;
  int packets_resp_to_init;
  int bytes_init_to_resp;
  int bytes_resp_to_init;
  int duplicates_init_to_resp;
  int duplicates_resp_to_init;
  int connection_closed_before_eof;
  tcp_packet** packets_from_init;
  tcp_packet** packets_from_resp;
} tcp_connect;


int global_p_number = 0;
int udp_packets = 0;
int tcp_packets = 0;
int other_packets = 0;
tcp_connect** connections;
int number_of_connections = 0;


int check_if_ack(int i, tcp_packet* tcp_packet, char type) {
  int acknowledged = 0;

  if (type == 'i') {
    for (int j = 2; j <= connections[i]->packets_resp_to_init; j++) {
      if (connections[i]->packets_from_resp[j]->tcp_ack_n == tcp_packet->tcp_seq+tcp_packet->payload_bytes) {
        acknowledged = 1;
        // Check if there is another packet with the same payload and sequenece number but that came later and was acknowledged
        // if that is the case this is a duplicate of the later packet and thus should not be included
        // Otherwise this packet is OK and should be included
        for (int k = connections[i]->packets_init_to_resp; k >= 3; k--) {
          if (connections[i]->packets_from_resp[j]->tcp_ack_n == connections[i]->packets_from_init[k]->tcp_seq+connections[i]->packets_from_init[k]->payload_bytes && connections[i]->packets_from_init[k]->global_package_number > tcp_packet->global_package_number) {
            acknowledged = 0;
            break;
          }
        }
        break;
      }
    }
  } else {
    for (int j = 3; j <= connections[i]->packets_init_to_resp; j++) {
      if (connections[i]->packets_from_init[j]->tcp_ack_n == tcp_packet->tcp_seq+tcp_packet->payload_bytes) {
        acknowledged = 1;
        // Check if there is another packet with the same payload and sequenece number but that came later and was acknowledged
        // if that is the case this is a duplicate of the later packet and thus should not be included
        // Otherwise this packet is OK and should be included
        for (int k = connections[i]->packets_resp_to_init; k >= 3; k--) {
          if (connections[i]->packets_from_init[j]->tcp_ack_n == connections[i]->packets_from_resp[k]->tcp_seq+connections[i]->packets_from_resp[k]->payload_bytes && connections[i]->packets_from_resp[k]->global_package_number > tcp_packet->global_package_number) {
            acknowledged = 0;
            break;
          }
        }
        break;
      }
    }
  }

  return acknowledged;
}


void find_duplicates_and_connection_close() {
  for (int i = 1; i <= number_of_connections; i++) {
    // the first 3 packets should be the 3-way handshake, otherwise discard all packages
    // in that connections// we would only have a new connection if there was a SYN alone sent by the initiator in the first place
    int handshake = 1;
    if (!(connections[i]->packets_from_init[1]->tcp_SYN == 1 && connections[i]->packets_from_init[1]->tcp_ACK == 0)) {
      handshake = 0;
    }
    if (!(connections[i]->packets_from_resp[1]->tcp_SYN == 1 && connections[i]->packets_from_resp[1]->tcp_ACK == 1 && (connections[i]->packets_from_resp[1]->tcp_ack_n == connections[i]->packets_from_init[1]->tcp_seq+1))) {
      handshake = 0;
    }
    if (!(connections[i]->packets_from_init[2]->tcp_SYN == 0 && connections[i]->packets_from_init[2]->tcp_ACK == 1 && (connections[i]->packets_from_init[2]->tcp_ack_n == connections[i]->packets_from_resp[1]->tcp_seq+1))) {
      handshake = 0;
    }

    // Go through the rest of the packets from each side checking if they were ack
    // Ignores packets with FIN, which have ack+1, rather than ack+payload ACKs, they will be checked for after

    // From initiator
    for (int j = 3; j <= connections[i]->packets_init_to_resp; j++) {
      if (handshake == 0) {
        connections[i]->packets_from_init[j]->include = 0;
      } else {
        int acknowledged = check_if_ack(i, connections[i]->packets_from_init[j], 'i');
        connections[i]->packets_from_init[j]->include = acknowledged;
      }
    }

    // From responder
    for (int j = 2; j <= connections[i]->packets_resp_to_init; j++) {
      if (handshake == 0) {
        connections[i]->packets_from_resp[j]->include = 0;
      } else {
        int acknowledged = check_if_ack(i, connections[i]->packets_from_resp[j], 'r');
        connections[i]->packets_from_resp[j]->include = acknowledged;
      }
    }
  }


  // Checking if connection closed correctly with the 4-way handshake (2 FIN and 2 ACK)
  // Update the packets with the FIN to be included in the output (even though no data expected)
  int end = 0;
  for (int i = 1; i <= number_of_connections; i++) {
    for (int j = 3; j <= connections[i]->packets_init_to_resp; j++) {
      if (connections[i]->packets_from_init[j]->tcp_FIN == 1 && connections[i]->packets_from_init[j]->tcp_ACK == 1) {
        end++; // one FIN sent
        // Check if ack + 1 received
        for (int k = 2; k <= connections[i]->packets_resp_to_init; k++) {
          if (connections[i]->packets_from_resp[k]->tcp_ack_n == connections[i]->packets_from_init[j]->tcp_seq+1) {
            end++; // ack received
            connections[i]->packets_from_init[j]->include = 1;
            break;
          }
        }
        break;
      }
    }

    for (int j = 2; j <= connections[i]->packets_resp_to_init; j++) {
      if (connections[i]->packets_from_resp[j]->tcp_FIN == 1 && connections[i]->packets_from_resp[j]->tcp_ACK == 1) {
        end++; // another FIN sent
        // Check if ack + 1 received
        for (int k = 3; k <= connections[i]->packets_init_to_resp; k++) {
          if (connections[i]->packets_from_init[k]->tcp_ack_n == connections[i]->packets_from_resp[j]->tcp_seq+1) {
            end++; // ack received
            connections[i]->packets_from_resp[j]->include = 1;
            break;
          }
        }
        break;
      }
    }

    if (end == 4) {
      connections[i]->connection_closed_before_eof = 0;
    } else {
      connections[i]->connection_closed_before_eof = 1;
    }

  }

  // Count the duplicates to be displayed in the metadata by looping through all packeages starting at the end and checking if seq number is smaller than an ACKed packet with a lower sequence number that came later
  // Only consider the packets that weren't ACKed as potential candidates for duplication
  // Excludes any packets without payload data since not considered duplicates given that no payload duplicated
  for (int i = 1; i <= number_of_connections; i++) {
    tcp_packet* latest_acked_init = connections[i]->packets_from_init[connections[i]->packets_init_to_resp];
    tcp_packet* latest_acked_resp = connections[i]->packets_from_resp[connections[i]->packets_resp_to_init];
    for (int j = connections[i]->packets_init_to_resp; j >= 3; j--) {
      if (connections[i]->packets_from_init[j]->include == 1) {
        latest_acked_init = connections[i]->packets_from_init[j];
      }
      if (connections[i]->packets_from_init[j]->include == 0 && connections[i]->packets_from_init[j]->global_package_number < latest_acked_init->global_package_number && connections[i]->packets_from_init[j]->tcp_seq >= latest_acked_init->tcp_seq && connections[i]->packets_from_init[j]->payload_bytes > 0) {
        connections[i]->duplicates_init_to_resp++;
        connections[i]->packets_from_init[j]->duplicate=1;
      }
    }

    for (int j = connections[i]->packets_resp_to_init; j >= 2; j--) {
      if (connections[i]->packets_from_resp[j]->include == 1) {
        latest_acked_init = connections[i]->packets_from_resp[j];
      }
      if (connections[i]->packets_from_resp[j]->include == 0 && connections[i]->packets_from_resp[j]->global_package_number < latest_acked_resp->global_package_number && connections[i]->packets_from_resp[j]->tcp_seq >= latest_acked_resp->tcp_seq  && connections[i]->packets_from_resp[j]->payload_bytes > 0) {
        connections[i]->duplicates_resp_to_init++;
        connections[i]->packets_from_resp[j]->duplicate=1;
      }
    }
  }

  // Now if you are not a duplicate and you hava a sequence + bytes lower than some ACK and you haven't been marked to be included yet, you may have been cumulatively ACK
  for (int i = 1; i <= number_of_connections; i++) {
    for (int j = 3; j <= connections[i]->packets_init_to_resp; j++) {
      if (connections[i]->packets_from_init[j]->include == 0 && connections[i]->packets_from_init[j]->duplicate == 0) {
        for (int k = 2; k <= connections[i]->packets_resp_to_init; k++) {
          if ((connections[i]->packets_from_resp[k]->include == 1) && (connections[i]->packets_from_resp[k]->tcp_ack_n > connections[i]->packets_from_init[j]->tcp_seq+connections[i]->packets_from_init[j]->payload_bytes) && connections[i]->packets_from_init[j]->payload_bytes>0) {
            connections[i]->packets_from_init[j]->include = 1;
            break;
          }
        }
      }
    }

    for (int j = 2; j <= connections[i]->packets_resp_to_init; j++) {
      if (connections[i]->packets_from_resp[j]->include == 0 && connections[i]->packets_from_resp[j]->duplicate == 0) {
        for (int k = 3; k <= connections[i]->packets_init_to_resp; k++) {
          if ((connections[i]->packets_from_init[k]->include == 1) && (connections[i]->packets_from_init[k]->tcp_ack_n > connections[i]->packets_from_resp[j]->tcp_seq+connections[i]->packets_from_resp[j]->payload_bytes) && connections[i]->packets_from_resp[j]->payload_bytes>0) {
            connections[i]->packets_from_resp[j]->include = 1;
            break;
          }
        }
      }
    }
  }


}

void printing_tcp_data_to_files() {
  // Creating the meta data file
  for (int i = 1; i <= number_of_connections; i++) {
    char buffer[50];
    sprintf(buffer, "%d.meta", i);
    FILE* f = fopen(buffer, "w");

    fputs("Initiator - IP Address: ", f);
    fputs(connections[i]->ip_src, f);

    fputs("\nResponder - IP Address: ", f);
    fputs(connections[i]->ip_des, f);

    sprintf(buffer, "%d", connections[i]->tcp_sport);
    fputs("\nInitiator - Port: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->tcp_dport);
    fputs("\nResponder - Port: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->packets_init_to_resp);
    fputs("\nPackets - Init. to Resp.: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->packets_resp_to_init);
    fputs("\nPackets - Resp. to Init.: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->bytes_init_to_resp);
    fputs("\nBytes - Init. to Resp.: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->bytes_resp_to_init);
    fputs("\nBytes - Resp. to Init.: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->duplicates_init_to_resp);
    fputs("\nDuplicates - Init. to Resp.: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->duplicates_resp_to_init);
    fputs("\nDuplicates - Resp. to Init.: ", f);
    fputs(buffer, f);

    sprintf(buffer, "%d", connections[i]->connection_closed_before_eof);
    fputs("\nConnection closed before EOF (1 = Yes, 0 = No): ", f);
    fputs(buffer, f);

    fclose(f);
  }

  // Creating the initiator to responder payload data output
  for (int i = 1; i <= number_of_connections; i++) {
    char buffer[50];
    sprintf(buffer, "%d.initiator", i);
    FILE* f = fopen(buffer, "w");

    for (int j = 1; j <= connections[i]->packets_init_to_resp; j++) {
      // Print only if data of payload > 0 and if flagged as ACKed and thus should be included
      if (connections[i]->packets_from_init[j]->include == 1 && connections[i]->packets_from_init[j]->payload_bytes > 0) {
        fputs(connections[i]->packets_from_init[j]->payload, f);
      }
    }
    fclose(f);
  }

  // Creating the responder to initiator payload data output
  for (int i = 1; i <= number_of_connections; i++) {
    char buffer[50];
    sprintf(buffer, "%d.responder", i);
    FILE* f = fopen(buffer, "w");

    for (int j = 1; j <= connections[i]->packets_resp_to_init; j++) {
      if (connections[i]->packets_from_resp[j]->include == 1 && connections[i]->packets_from_resp[j]->payload_bytes > 0) {
        // Print only if data of payload > 0 and if flagged as ack and should be included
        fputs(connections[i]->packets_from_resp[j]->payload, f);
      }
    }
    fclose(f);
  }

}


u_char* payload_to_str(const u_char *payload_ptr, int len) {
	const u_char *c = payload_ptr;
  u_char* buffer = malloc(10000*sizeof(u_char));
  buffer[0]='\0';
  if (len > 0) {
    int i = 0;
    for(i = 0; i < len; i++) {
  		if (isprint(*c)) {
        buffer[i] = *c;
  		} else {
        buffer[i] = *c;
      }
  		c++;
  	}
    buffer[i] = '\0';
	}
  return buffer;
}

void packetparser(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    struct ether_header *e_header;
    e_header = (struct ether_header*) packet;
    u_short p_type = e_header->ether_type;

    if (ntohs(p_type) == ETHERTYPE_IP) {
        global_p_number++;
        // Parsing the IP header
        char* buffer;
        const struct ip* ip;
        ip = (struct ip*)(packet + sizeof(struct ether_header));
        char ip_src[100];
        char ip_des[100];
        buffer = inet_ntoa(ip->ip_src);
        strcpy(ip_src, buffer);
        buffer = inet_ntoa(ip->ip_dst);
        strcpy(ip_des, buffer);
        u_char ip_protocol = ip->ip_p;

        if (ip_protocol == IPPROTO_TCP) {
          const struct tcphdr* tcp;
          tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
          uint16_t tcp_sport = ntohs(tcp->th_sport);
          uint16_t tcp_dport = ntohs(tcp->th_dport);
          u_short tcp_chksum = ntohs(tcp->th_sum);

          // Calculating payload size
          int ip_total_bytes = ntohs(ip->ip_len);
          int ip_hdr_bytes = ip->ip_hl*32/8;
          int tcp_hdr_bytes = tcp->th_off*32/8;
          int payload_bytes = ip_total_bytes - ip_hdr_bytes - tcp_hdr_bytes;

          // Parsing data on the patload and creating pointer to formatted data
          const u_char *payload_ptr = (u_char *)(packet + sizeof(struct ether_header) + ip_total_bytes - payload_bytes);
          u_char* payload_data = payload_to_str(payload_ptr, payload_bytes);

          // Increasing number of TCP packets received
          tcp_packets++;

          // Retrieving the TCP flags from the TCP header
          u_char flags = tcp->th_flags;
          int tcp_FIN = 0;
          int tcp_SYN = 0;
          int tcp_RST = 0;
          int tcp_PUSH = 0;
          int tcp_ACK = 0;
          int tcp_URG = 0;
          if ((flags & 0x000F) == 0x0001) tcp_FIN = 1;
          if ((flags & 0x000F) == 0x0002) tcp_SYN = 1;
          if ((flags & 0x000F) == 0x0004) tcp_RST = 1;
          if ((flags & 0x000F) == 0x0008) tcp_PUSH = 1;
          if ((flags & 0x00F0) == 0x0010) tcp_ACK = 1;
          if ((flags & 0x00F0) == 0x0020) tcp_URG = 1;

          // Getting the sequence number and acknowledge number of the packets
          long tcp_seq = ntohl(tcp->th_seq);
          long tcp_ack_n = ntohl(tcp->th_ack);

          // Creating new TCP packet with relevant information
          tcp_packet* tcp_pkt = malloc(sizeof(tcp_packet));
          strcpy(tcp_pkt->ip_src, ip_src);
          strcpy(tcp_pkt->ip_des, ip_des);
          tcp_pkt->tcp_sport = tcp_sport;
          tcp_pkt->tcp_dport = tcp_dport;
          tcp_pkt->tcp_FIN = tcp_FIN;
          tcp_pkt->tcp_SYN = tcp_SYN;
          tcp_pkt->tcp_RST = tcp_RST;
          tcp_pkt->tcp_PUSH = tcp_PUSH;
          tcp_pkt->tcp_ACK = tcp_ACK;
          tcp_pkt->tcp_URG = tcp_URG;
          tcp_pkt->tcp_seq = tcp_seq;
          tcp_pkt->tcp_ack_n = tcp_ack_n;
          tcp_pkt->payload_bytes = payload_bytes;
          tcp_pkt->payload = payload_data;
          tcp_pkt->include = 1; // include by default in printout
          tcp_pkt->duplicate = 0; // mark as zero my default, will check at the end
          tcp_pkt->global_package_number = global_p_number;
          // printf("TCP PACKET FIN: %d\n", tcp_pkt->tcp_FIN);
          // printf("TCP SEQ: %ld\n", tcp_pkt->tcp_seq);

          // Determining if packet is for new connection or former
          if (tcp_SYN == 1 && tcp_ACK == 0) {
            // Creating new connection
            number_of_connections++;
            tcp_connect* current = malloc(sizeof(tcp_connect));
            current->number = number_of_connections;
            strcpy(current->ip_src, ip_src);
            strcpy(current->ip_des, ip_des);
            current->tcp_sport = tcp_sport;
            current->tcp_dport = tcp_dport;
            current->packets_init_to_resp = 1;
            current->packets_resp_to_init = 0;
            current->bytes_init_to_resp = 0;
            current->bytes_resp_to_init = 0;
            current->duplicates_init_to_resp = 0;
            current->duplicates_resp_to_init = 0;
            current->connection_closed_before_eof = -1;
            current->packets_from_init = malloc(sizeof(tcp_packet*)*1000);
            current->packets_from_resp = malloc(sizeof(tcp_packet*)*1000);
            current->packets_from_init[current->packets_init_to_resp] = tcp_pkt;
            connections[number_of_connections] = current;
          } else {
            tcp_connect* current;
            for (int i = 1; i <= number_of_connections; i++) {
              current = connections[i];
              if ((strcmp(current->ip_src, ip_src) == 0) && (strcmp(current->ip_des, ip_des) == 0) && (current->tcp_sport == tcp_sport) && (current->tcp_dport == tcp_dport)) {
                // Connection match: Initiator to Responder
                current = connections[i];
                current->packets_init_to_resp++;
                current->bytes_init_to_resp += payload_bytes;
                current->packets_from_init[current->packets_init_to_resp] = tcp_pkt;
                break;
              }

              if ((strcmp(current->ip_des, ip_src) == 0) && (strcmp(current->ip_src, ip_des) == 0) && (current->tcp_dport == tcp_sport) && (current->tcp_sport == tcp_dport)) {
                // Connection match: Responder to Initiator
                current = connections[i];
                current->packets_resp_to_init++;
                current->bytes_resp_to_init += payload_bytes;
                current->packets_from_resp[current->packets_resp_to_init] = tcp_pkt;
                break;
              }
            }
          }
        }
    }
}

int main(int argc, char *argv[]) {
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

  connections = malloc(sizeof(tcp_connect*)*10000);
  pcap_loop(pf,-1,packetparser,NULL);

  find_duplicates_and_connection_close();

  printing_tcp_data_to_files();


  exit(0);
}
