#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>      
#include <sys/types.h> 
#include <netinet/in.h>

// This is the main callback function for libpcap.
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @brief Resets the internal packet counter back to zero.
 */
void reset_packet_counter();

#endif // PACKET_PARSER_H