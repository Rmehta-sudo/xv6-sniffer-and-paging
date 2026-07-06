// src/packet_storage.h

#ifndef PACKET_STORAGE_H
#define PACKET_STORAGE_H

#include <pcap.h>

// The maximum number of packets we can store in a single session.
#define MAX_PACKETS 10000

// A structure to hold a copy of the packet data and its header.
typedef struct {
    struct pcap_pkthdr header;
    u_char *data;
} stored_packet_t;

// Global array of pointers to our stored packets.
extern stored_packet_t *packet_storage[MAX_PACKETS];
// Counter for the number of packets currently stored.
extern int stored_packet_count;

/**
 * @brief Creates a deep copy of a packet and stores it in the global storage.
 * @param header The pcap header of the packet.
 * @param packet The raw packet data.
 */
void store_packet(const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @brief Frees all memory allocated for the stored packets from the last session.
 */
void free_packet_storage();

#endif // PACKET_STORAGE_H
