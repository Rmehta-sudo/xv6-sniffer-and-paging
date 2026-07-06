#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "inspector.h"
#include "packet_storage.h"
#include "colors.h"

// --- Internal Function Prototypes ---
static void print_full_hex_dump(const u_char *data, int len);
static void print_packet_details(int packet_id);
static void print_session_summary();
static void get_summary_info(const u_char *packet_data, char *buffer, size_t buffer_len);

// --- Public Functions ---

void inspect_session() {
    if (stored_packet_count == 0) {
        printf("\n" C_BOLD "[C-Shark] No packets in storage. Run a sniffing session first.\n" C_RESET);
        return;
    }

    print_session_summary();

    int choice = 0;
    printf("\nEnter Packet ID to inspect (or 0 to return): ");
    if (scanf("%d", &choice) != 1) {
        while (getchar() != '\n'); // Clear buffer
        printf("Invalid input.\n");
        return;
    }

    if (choice == 0) {
        return;
    }

    if (choice < 1 || choice > stored_packet_count) {
        printf("Invalid Packet ID.\n");
        return;
    }

    print_packet_details(choice);
}


// --- Internal Helper Functions ---

static void print_session_summary() {
    printf("\n--- Stored Packets Summary ---\n");
    char summary_buf[256];
    for (int i = 0; i < stored_packet_count; i++) {
        stored_packet_t *sp = packet_storage[i];
        get_summary_info(sp->data, summary_buf, sizeof(summary_buf));
        printf(C_L4 "ID: %-5d" C_L2 "| Len: %-5d bytes " C_L3" | %s\n",
               i + 1, sp->header.len, summary_buf);
    }
}

static void print_packet_details(int packet_id) {
    stored_packet_t *sp = packet_storage[packet_id - 1];
    const u_char *packet = sp->data;
    const struct pcap_pkthdr *header = &sp->header;

    printf(C_DIM "\n--------------------------------------------------------------------" C_RESET "\n");
    printf(C_PKT_HDR C_BOLD "Inspecting Packet #%d\n", packet_id);
    printf(C_PKT_HDR "Timestamp: %ld.%06ld | Captured Length: %d bytes\n" C_RESET,
           header->ts.tv_sec, header->ts.tv_usec, header->len);
    printf(C_DIM "--------------------------------------------------------------------" C_RESET "\n");

    // --- Layer 2: Ethernet ---
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);
    printf(C_L2 C_BOLD "Layer 2: Ethernet Header\n" C_RESET);
    printf(C_L2 "  ├─ Dst MAC: " C_BOLD "%02x:%02x:%02x:%02x:%02x:%02x\n" C_RESET,
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    printf(C_L2 "  ├─ Src MAC: " C_BOLD "%02x:%02x:%02x:%02x:%02x:%02x\n" C_RESET,
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf(C_L2 "  └─ EtherType: " C_BOLD "0x%04x " C_RESET, ether_type);
    if (ether_type == ETHERTYPE_IP) printf("(IPv4)\n");
    else if (ether_type == ETHERTYPE_IPV6) printf("(IPv6)\n");
    else if (ether_type == ETHERTYPE_ARP) printf("(ARP)\n");
    else printf("(Unknown)\n");

    printf(C_DIM "  Raw: ");
    for (int i = 0; i < (int)sizeof(struct ether_header); ++i) printf("%02x ", packet[i]);
    printf("\n" C_RESET);

    // --- Layer 3: IPv4 ---
    if (ether_type == ETHERTYPE_IP) {
        const u_char *ip_ptr = packet + sizeof(struct ether_header);
        struct ip *ip_header = (struct ip *)ip_ptr;
        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
        uint16_t frag = ntohs(ip_header->ip_off);
        int df = (frag & IP_DF) ? 1 : 0;
        int mf = (frag & IP_MF) ? 1 : 0;
        int frag_off = (frag & IP_OFFMASK) * 8;
        
        printf(C_L3 C_BOLD "\nLayer 3: IPv4 Header\n" C_RESET);
        printf(C_L3 "  ├─ Version: " C_BOLD "%d\n" C_RESET, ip_header->ip_v);
        printf(C_L3 "  ├─ Header Length: " C_BOLD "%d bytes\n" C_RESET, ip_header->ip_hl * 4);
        printf(C_L3 "  ├─ Total Length: " C_BOLD "%d\n" C_RESET, ntohs(ip_header->ip_len));
        printf(C_L3 "  ├─ TTL: " C_BOLD "%d\n" C_RESET, ip_header->ip_ttl);
        printf(C_L3 "  ├─ Protocol: " C_BOLD "%d " C_RESET, ip_header->ip_p);
        if(ip_header->ip_p == IPPROTO_TCP) printf("(TCP)\n");
        else if(ip_header->ip_p == IPPROTO_UDP) printf("(UDP)\n");
        else printf("(Other)\n");
        printf(C_L3 "  ├─ Src IP: " C_BOLD "%s\n" C_RESET, src_ip_str);
        printf(C_L3 "  ├─ Dst IP: " C_BOLD "%s\n" C_RESET, dst_ip_str);
        printf(C_L3 "  └─ Flags: " C_BOLD "%s%s" C_RESET " | Frag Off: " C_BOLD "%d\n" C_RESET,
               df ? "DF" : "",
               mf ? (df ? ",MF" : "MF") : (df ? "" : "None"),
               frag_off);

        printf(C_DIM "  Raw: ");
        for (int i = 0; i < ip_header->ip_hl * 4; ++i) printf("%02x ", ip_ptr[i]);
        printf("\n" C_RESET);

        // --- Layer 4: TCP / UDP ---
        if (ip_header->ip_p == IPPROTO_TCP) {
             const u_char *tcp_ptr = ip_ptr + (ip_header->ip_hl * 4);
             struct tcphdr *tcp_header = (struct tcphdr *)tcp_ptr;
             printf(C_L4 C_BOLD "\nLayer 4: TCP Header\n" C_RESET);
             printf(C_L4 "  ├─ Src Port: " C_BOLD "%d\n" C_RESET, ntohs(tcp_header->th_sport));
             printf(C_L4 "  ├─ Dst Port: " C_BOLD "%d\n" C_RESET, ntohs(tcp_header->th_dport));
             printf(C_L4 "  ├─ Sequence Number: " C_BOLD "%u\n" C_RESET, ntohl(tcp_header->th_seq));
             printf(C_L4 "  ├─ Ack Number: " C_BOLD "%u\n" C_RESET, ntohl(tcp_header->th_ack));
             printf(C_L4 "  ├─ Header Length: " C_BOLD "%d bytes\n" C_RESET, tcp_header->th_off * 4);
             printf(C_L4 "  └─ Checksum: " C_BOLD "0x%04x\n" C_RESET, ntohs(tcp_header->th_sum));

             printf(C_DIM "  Raw: ");
             int tcp_hl = tcp_header->th_off * 4;
             for (int i = 0; i < tcp_hl; ++i) printf("%02x ", tcp_ptr[i]);
             printf("\n" C_RESET);
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            const u_char *udp_ptr = ip_ptr + (ip_header->ip_hl * 4);
            struct udphdr *udp_header = (struct udphdr *)udp_ptr;
            printf(C_L4 C_BOLD "\nLayer 4: UDP Header\n" C_RESET);
            printf(C_L4 "  ├─ Src Port: " C_BOLD "%d\n" C_RESET, ntohs(udp_header->uh_sport));
            printf(C_L4 "  ├─ Dst Port: " C_BOLD "%d\n" C_RESET, ntohs(udp_header->uh_dport));
            printf(C_L4 "  ├─ Length: " C_BOLD "%d\n" C_RESET, ntohs(udp_header->uh_ulen));
            printf(C_L4 "  └─ Checksum: " C_BOLD "0x%04x\n" C_RESET, ntohs(udp_header->uh_sum));

            printf(C_DIM "  Raw: ");
            for (int i = 0; i < 8; ++i) printf("%02x ", udp_ptr[i]);
            printf("\n" C_RESET);
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        const u_char *ip6_ptr = packet + sizeof(struct ether_header);
        struct ip6_hdr *ip6 = (struct ip6_hdr *)ip6_ptr;
        char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_src), src6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst6, INET6_ADDRSTRLEN);
        uint16_t payload_len = ntohs(ip6->ip6_plen);
        uint32_t vtc_flow = ntohl(*(uint32_t *)ip6_ptr);
        int traffic_class = (vtc_flow >> 20) & 0xFF;
        int flow_label = vtc_flow & 0x000FFFFF;

        printf(C_L3 C_BOLD "\nLayer 3: IPv6 Header\n" C_RESET);
        printf(C_L3 "  ├─ Src IP: " C_BOLD "%s\n" C_RESET, src6);
        printf(C_L3 "  ├─ Dst IP: " C_BOLD "%s\n" C_RESET, dst6);
        printf(C_L3 "  ├─ Next Header: " C_BOLD "%d\n" C_RESET, ip6->ip6_nxt);
        printf(C_L3 "  ├─ Hop Limit: " C_BOLD "%d\n" C_RESET, ip6->ip6_hlim);
        printf(C_L3 "  ├─ Traffic Class: " C_BOLD "%d\n" C_RESET, traffic_class);
        printf(C_L3 "  └─ Flow Label: " C_BOLD "0x%05x\n" C_RESET, flow_label);

        printf(C_DIM "  Raw: ");
        for (int i = 0; i < (int)sizeof(struct ip6_hdr); ++i) printf("%02x ", ip6_ptr[i]);
        printf("\n" C_RESET);

        // L4 for IPv6 when TCP/UDP
        if (ip6->ip6_nxt == IPPROTO_TCP) {
            const u_char *tcp_ptr = ip6_ptr + sizeof(struct ip6_hdr);
            struct tcphdr *tcp = (struct tcphdr *)tcp_ptr;
            printf(C_L4 C_BOLD "\nLayer 4: TCP Header\n" C_RESET);
            printf(C_L4 "  ├─ Src Port: " C_BOLD "%d\n" C_RESET, ntohs(tcp->th_sport));
            printf(C_L4 "  ├─ Dst Port: " C_BOLD "%d\n" C_RESET, ntohs(tcp->th_dport));
            printf(C_L4 "  ├─ Sequence Number: " C_BOLD "%u\n" C_RESET, ntohl(tcp->th_seq));
            printf(C_L4 "  ├─ Ack Number: " C_BOLD "%u\n" C_RESET, ntohl(tcp->th_ack));
            printf(C_L4 "  ├─ Header Length: " C_BOLD "%d bytes\n" C_RESET, tcp->th_off * 4);
            printf(C_L4 "  └─ Checksum: " C_BOLD "0x%04x\n" C_RESET, ntohs(tcp->th_sum));

            printf(C_DIM "  Raw: ");
            int tcp_hl = tcp->th_off * 4;
            for (int i = 0; i < tcp_hl; ++i) printf("%02x ", tcp_ptr[i]);
            printf("\n" C_RESET);
        } else if (ip6->ip6_nxt == IPPROTO_UDP) {
            const u_char *udp_ptr = ip6_ptr + sizeof(struct ip6_hdr);
            struct udphdr *udp = (struct udphdr *)udp_ptr;
            printf(C_L4 C_BOLD "\nLayer 4: UDP Header\n" C_RESET);
            printf(C_L4 "  ├─ Src Port: " C_BOLD "%d\n" C_RESET, ntohs(udp->uh_sport));
            printf(C_L4 "  ├─ Dst Port: " C_BOLD "%d\n" C_RESET, ntohs(udp->uh_dport));
            printf(C_L4 "  ├─ Length: " C_BOLD "%d\n" C_RESET, ntohs(udp->uh_ulen));
            printf(C_L4 "  └─ Checksum: " C_BOLD "0x%04x\n" C_RESET, ntohs(udp->uh_sum));

            printf(C_DIM "  Raw: ");
            for (int i = 0; i < 8; ++i) printf("%02x ", udp_ptr[i]);
            printf("\n" C_RESET);
        }
    } else if (ether_type == ETHERTYPE_ARP) {
        const u_char *arp_ptr = packet + sizeof(struct ether_header);
        struct ether_arp *arp = (struct ether_arp *)arp_ptr;
        char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, sip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp->arp_tpa, tip, INET_ADDRSTRLEN);
        const char *op = (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) ? "Request (1)" : "Reply (2)";

        printf(C_L3 C_BOLD "\nLayer 3: ARP\n" C_RESET);
        printf(C_L3 "  ├─ Operation: " C_BOLD "%s\n" C_RESET, op);
        printf(C_L3 "  ├─ Sender MAC: " C_BOLD "%02x:%02x:%02x:%02x:%02x:%02x" C_RESET " | Sender IP: " C_BOLD "%s\n" C_RESET,
               arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5], sip);
        printf(C_L3 "  ├─ Target MAC: " C_BOLD "%02x:%02x:%02x:%02x:%02x:%02x" C_RESET " | Target IP: " C_BOLD "%s\n" C_RESET,
               arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5], tip);
        printf(C_L3 "  └─ HW Type: " C_BOLD "%u" C_RESET " | Proto Type: " C_BOLD "0x%04x" C_RESET " | HW Len: " C_BOLD "%u" C_RESET " | Proto Len: " C_BOLD "%u\n" C_RESET,
               ntohs(arp->ea_hdr.ar_hrd), ntohs(arp->ea_hdr.ar_pro), arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln);

        printf(C_DIM "  Raw: ");
        for (int i = 0; i < (int)sizeof(struct ether_arp); ++i) printf("%02x ", arp_ptr[i]);
        printf("\n" C_RESET);
    }

    // --- Full Hex Dump ---
    printf(C_L7 C_BOLD "\nFull Packet Hex Dump (%d bytes)\n" C_RESET, header->len);
    print_full_hex_dump(packet, header->len);

    printf(C_DIM "--------------------------------------------------------------------" C_RESET "\n");
}


static void print_full_hex_dump(const u_char *data, int len) {
    for (int i = 0; i < len; ++i) {
        if (i % 16 == 0) printf(C_DIM "  %04x: " C_RESET, i);
        printf(C_DATA "%02x " C_RESET, data[i]);
        if (i % 16 == 7) printf(" ");
        if (i % 16 == 15 || i == len - 1) {
            // Print ASCII representation
            int padding = (i % 16 == 15) ? 0 : 15 - (i % 16);
            for(int p=0; p<padding; ++p) printf("   ");
            if (padding >= 8) printf(" ");

            printf(C_DATA "| " C_RESET);
            for (int j = i - (i % 16); j <= i; ++j) {
                printf(C_BOLD "%c" C_RESET, isprint(data[j]) ? data[j] : '.');
            }
            printf("\n");
        }
    }
}

// Generates a one-line summary string for a given packet
static void get_summary_info(const u_char *packet_data, char *buffer, size_t buffer_len) {
    struct ether_header *eth = (struct ether_header *)packet_data;
    uint16_t ether_type = ntohs(eth->ether_type);

    if (ether_type == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet_data + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            snprintf(buffer, buffer_len, "IPv4/TCP   %s:%d -> %s:%d",
                     src_ip, ntohs(tcp->th_sport), dst_ip, ntohs(tcp->th_dport));
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(packet_data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            snprintf(buffer, buffer_len, "IPv4/UDP   %s:%d -> %s:%d",
                     src_ip, ntohs(udp->uh_sport), dst_ip, ntohs(udp->uh_dport));
        } else {
            snprintf(buffer, buffer_len, "IPv4       %s -> %s", src_ip, dst_ip);
        }
    } else if (ether_type == ETHERTYPE_ARP) {
        struct ether_arp *arp = (struct ether_arp *)(packet_data + sizeof(struct ether_header));
        char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, sip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp->arp_tpa, tip, INET_ADDRSTRLEN);
        snprintf(buffer, buffer_len, "ARP        %s -> %s", sip, tip);
    } else if (ether_type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet_data + sizeof(struct ether_header));
        char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst6, INET6_ADDRSTRLEN);
        const char *nh = (ip6->ip6_nxt == IPPROTO_TCP) ? "TCP" : (ip6->ip6_nxt == IPPROTO_UDP) ? "UDP" : "Other";
        snprintf(buffer, buffer_len, "IPv6/%s   %s -> %s", nh, src6, dst6);
    } else {
        snprintf(buffer, buffer_len, "Other      Unknown L3 protocol");
    }
}