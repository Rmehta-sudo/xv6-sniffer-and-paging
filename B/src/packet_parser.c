#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

#include "packet_parser.h"
#include "colors.h" // Include our new color definitions
#include "packet_storage.h" // ADD: Include the new storage header

// --- Internal Helper Function Prototypes ---
void print_mac_address(const u_char *mac);
const char* get_service_name(int port);
void print_tcp_flags(u_char flags);
void print_payload(const u_char *payload, int len);
void parse_ethernet(const u_char *packet);
void parse_ipv4(const u_char *packet);
void parse_ipv6(const u_char *packet);
void parse_arp(const u_char *packet);
void parse_tcp(const u_char *packet, int ip_header_len, int total_ip_len);
void parse_udp(const u_char *packet, int ip_header_len, int total_ip_len);

static int packet_count = 0;

void reset_packet_counter() {
    packet_count = 0;
}


void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    packet_count++; // This also uses the module-level counter

    store_packet(header, packet);

    printf(C_DIM "--------------------------------------------------------------------" C_RESET "\n");
    printf(C_PKT_HDR C_BOLD "Packet #%-5d| Timestamp: %ld.%06ld | Length: %d bytes\n",
           packet_count, header->ts.tv_sec, header->ts.tv_usec, header->len);

    parse_ethernet(packet);
}


void parse_ethernet(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    int ether_type = ntohs(eth_header->ether_type);
    const u_char *next_layer_packet = packet + sizeof(struct ether_header);

    printf(C_L2 " L2 " C_L2 "(Ethernet)   | Dst MAC: ");
    print_mac_address(eth_header->ether_dhost);
    printf(C_L2 " | Src MAC: ");
    print_mac_address(eth_header->ether_shost);
    
    switch (ether_type) {
        case ETHERTYPE_IP:   printf(C_L2 " | Type: IPv4 (0x%04x)\n", ether_type); parse_ipv4(next_layer_packet); break;
        case ETHERTYPE_IPV6: printf(C_L2 " | Type: IPv6 (0x%04x)\n", ether_type); parse_ipv6(next_layer_packet); break;
        case ETHERTYPE_ARP:  printf(C_L2 " | Type: ARP (0x%04x)\n", ether_type);  parse_arp(next_layer_packet);  break;
        default:             printf(C_L2 " | Type: Unknown (0x%04x)\n", ether_type); break;
    }
}

void parse_ipv4(const u_char *packet) {
    struct ip *ip_header = (struct ip *)packet;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    int ip_header_len = ip_header->ip_hl * 4;
    int total_len = ntohs(ip_header->ip_len);
    const u_char *next_layer_packet = packet + ip_header_len;

    // IPv4 flags and fragment offset
    uint16_t frag = ntohs(ip_header->ip_off);
    int df = (frag & IP_DF) ? 1 : 0;
    int mf = (frag & IP_MF) ? 1 : 0;
    int frag_off = (frag & IP_OFFMASK) * 8; // in bytes

    const char *proto_name = (ip_header->ip_p == IPPROTO_TCP) ? "TCP" :
                             (ip_header->ip_p == IPPROTO_UDP) ? "UDP" : "Other";

    printf(C_L3 " L3 " C_L3 "(IPv4)       | %s → %s\n", src_ip, dst_ip);
    printf(C_DIM "                | Protocol: %s (%d) | TTL: %d | ID: 0x%04x | Hdr Len: %d bytes\n" C_RESET,
           proto_name, ip_header->ip_p, ip_header->ip_ttl, ntohs(ip_header->ip_id), ip_header_len);
    printf(C_DIM "                | Total Len: %d | Flags: %s%s | Frag Off: %d\n" C_RESET,
           total_len,
           df ? "DF" : "",
           mf ? (df ? ",MF" : "MF") : (df ? "" : "None"),
           frag_off);
    
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: parse_tcp(next_layer_packet, ip_header_len, total_len); break;
        case IPPROTO_UDP: parse_udp(next_layer_packet, ip_header_len, total_len); break;
    }
}

void parse_ipv6(const u_char *packet) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)packet;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    uint16_t payload_len = ntohs(ip6_header->ip6_plen);
    const u_char *next_layer_packet = packet + sizeof(struct ip6_hdr);

    // Extract traffic class and flow label
    uint32_t vtc_flow = ntohl(*(uint32_t *)packet);
    int traffic_class = (vtc_flow >> 20) & 0xFF;
    int flow_label = vtc_flow & 0x000FFFFF;

    const char *nh_name = (ip6_header->ip6_nxt == IPPROTO_TCP) ? "TCP" :
                          (ip6_header->ip6_nxt == IPPROTO_UDP) ? "UDP" : "Other";

    printf(C_L3 " L3 " C_L3 "(IPv6)       | %s → %s\n", src_ip, dst_ip);
    printf(C_DIM "                | Next Header: %s (%d) | Hop Limit: %d | Traffic Class: %d | Flow Label: 0x%05x | Payload Len: %d\n" C_RESET,
           nh_name, ip6_header->ip6_nxt, ip6_header->ip6_hlim, traffic_class, flow_label, payload_len);
    
    switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP: parse_tcp(next_layer_packet, 40, payload_len + 40); break;
        case IPPROTO_UDP: parse_udp(next_layer_packet, 40, payload_len + 40); break;
    }
}

void parse_arp(const u_char *packet) {
    struct ether_arp *arp_header = (struct ether_arp *)packet;
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);
    const char* op = ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REQUEST ? "REQUEST" : "REPLY";

    printf(C_L3 " L3 " C_L3 "(ARP)        | Operation: " C_BOLD "%s" C_RESET "\n", op);
    printf("                | Sender: ");
    print_mac_address(arp_header->arp_sha);
    printf(" (%s)\n", sender_ip);
    printf("                | Target: ");
    print_mac_address(arp_header->arp_tha);
    printf(" (%s)\n", target_ip);
    printf(C_DIM "                | HW Type: %u | Proto Type: 0x%04x | HW Len: %u | Proto Len: %u\n" C_RESET,
           ntohs(arp_header->ea_hdr.ar_hrd), ntohs(arp_header->ea_hdr.ar_pro),
           arp_header->ea_hdr.ar_hln, arp_header->ea_hdr.ar_pln);
}

void parse_tcp(const u_char *packet, int ip_header_len, int total_ip_len) {
    struct tcphdr *tcp_header = (struct tcphdr *)packet;
    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);
    int tcp_header_len = tcp_header->th_off * 4;

    printf(C_L4 " L4 " C_L4 "(TCP)        | Port: %d (%s) → %d (%s) ",
           src_port, get_service_name(src_port), dst_port, get_service_name(dst_port));
    print_tcp_flags(tcp_header->th_flags);
    printf("\n");
    printf(C_DIM "                | Seq: %u | Ack: %u | Win: %d | Hdr Len: %d bytes | Checksum: 0x%04x\n" C_RESET,
           ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack), ntohs(tcp_header->th_win), tcp_header_len, ntohs(tcp_header->th_sum));

    int payload_len = total_ip_len - ip_header_len - tcp_header_len;
    if (payload_len > 0) {
        const u_char *payload = packet + tcp_header_len;
        printf(C_L7 " L7 " C_RESET "(Payload)    | %d bytes of %s data\n", payload_len, get_service_name(dst_port));
        print_payload(payload, payload_len);
    }
}

void parse_udp(const u_char *packet, int ip_header_len, int total_ip_len) {
    (void)ip_header_len; 
    (void)total_ip_len;
    struct udphdr *udp_header = (struct udphdr *)packet;
    int src_port = ntohs(udp_header->uh_sport);
    int dst_port = ntohs(udp_header->uh_dport);
    int udp_len = ntohs(udp_header->uh_ulen);

    printf(C_L4 " L4 " C_L4 "(UDP)        | Port: %d (%s) → %d (%s)\n",
           src_port, get_service_name(src_port), dst_port, get_service_name(dst_port));
    printf(C_DIM "                | Length: %d | Checksum: 0x%04x\n" C_RESET,
           udp_len, ntohs(udp_header->uh_sum));

    int payload_len = udp_len - 8;
    if (payload_len > 0) {
        const u_char *payload = packet + 8;
        printf(C_L7 " L7 " C_L7 "(Payload)    | %d bytes of %s data\n", payload_len, get_service_name(dst_port));
        print_payload(payload, payload_len);
    }
}

// --- Helper Functions ---

void print_mac_address(const u_char *mac) {
    printf(C_BOLD "%02x:%02x:%02x:%02x:%02x:%02x" C_RESET,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* get_service_name(int port) {
    switch(port) {
        case 80: return "HTTP"; case 443: return "HTTPS"; case 53: return "DNS";
        case 20: case 21: return "FTP"; case 22: return "SSH"; case 25: return "SMTP";
        default: return "Other";
    }
}

void print_tcp_flags(u_char flags) {
    printf(C_BOLD);
    if (flags & TH_FIN) printf("[FIN] ");
    if (flags & TH_SYN) printf("[SYN] ");
    if (flags & TH_RST) printf("[RST] ");
    if (flags & TH_PUSH) printf("[PSH] ");
    if (flags & TH_ACK) printf("[ACK] ");
    if (flags & TH_URG) printf("[URG] ");
    printf(C_RESET);
}

void print_payload(const u_char *payload, int len) {
    int line_width = 16;
    int len_to_print = len > 64 ? 64 : len;

    for (int i = 0; i < len_to_print; i++) {
        if (i % line_width == 0) printf(C_DIM "                | " C_RESET);
        
        printf(C_DATA "%02x " C_RESET, payload[i]);

        if (i % line_width == line_width - 1 || i == len_to_print - 1) {
            if (i % line_width != line_width - 1) {
                for (int j = 0; j < (line_width - 1 - (i % line_width)); j++) {
                    printf("   ");
                }
            }
            printf(C_DATA " " C_RESET);
            for (int j = i - (i % line_width); j <= i; j++) {
                printf(C_BOLD "%c" C_RESET, isprint(payload[j]) ? payload[j] : '.');
            }
            printf("\n");
        }
    }
}