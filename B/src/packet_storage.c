// src/packet_storage.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packet_storage.h"

// Define the global storage variables.
stored_packet_t *packet_storage[MAX_PACKETS];
int stored_packet_count = 0;

void store_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (stored_packet_count >= MAX_PACKETS) {
        // Stop storing if we've reached the limit.
        return;
    }

    // 1. Allocate memory for the container struct.
    stored_packet_t *sp = malloc(sizeof(stored_packet_t));
    if (sp == NULL) {
        perror("Failed to allocate memory for stored packet");
        return;
    }

    // 2. Allocate memory for the packet data itself.
    sp->data = malloc(header->caplen);
    if (sp->data == NULL) {
        perror("Failed to allocate memory for packet data");
        free(sp); // Clean up the container
        return;
    }

    // 3. Copy the header and packet data.
    sp->header = *header;
    memcpy(sp->data, packet, header->caplen);

    // 4. Add the new packet to our storage array.
    packet_storage[stored_packet_count] = sp;
    stored_packet_count++;
}

void free_packet_storage() {
    if (stored_packet_count == 0) {
        return; // Nothing to free.
    }
    
    printf( "\n[C-Shark] Freeing memory from last session (%d packets)...\n", stored_packet_count);

    for (int i = 0; i < stored_packet_count; i++) {
        // Free the packet data first.
        free(packet_storage[i]->data);
        // Then free the container struct.
        free(packet_storage[i]);
    }

    // Reset the counter for the next session.
    stored_packet_count = 0;
}
