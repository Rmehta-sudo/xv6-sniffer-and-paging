#include "pcap_handler.h"
#include "packet_parser.h" // For the parse_packet callback
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"

// Global handle for the sniffing session.
// This is needed so the signal handler can access it.
// The global handle definition remains
pcap_t *handle;

// MOD: Function signature changed to return an int
int start_sniffing(char *device_name, const char *filter_exp) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Reset stop flag at the beginning of each session
    g_stop_sniffing = 0;

    handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[C-Shark] Couldn't open device %s: %s\n", device_name, errbuf);
        return 0;
    }

    // --- NEW: FILTERING LOGIC ---
    struct bpf_program fp; // Holds the compiled filter
    if (filter_exp != NULL) {
        printf("[C-Shark] Applying filter: \"%s\"\n", filter_exp);
        // Compile the filter string into a filter program
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "[C-Shark] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            return 0;
        }
        // Apply the compiled filter
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "[C-Shark] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_freecode(&fp); // Free memory on error
            pcap_close(handle);
            return 0;
        }
    }
    // --- END OF NEW LOGIC ---

    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] Error setting non-blocking mode: %s\n", errbuf);
        pcap_close(handle);
        return 0;
    }

    printf("[C-Shark] Sniffing on %s... (Press Ctrl+C to stop, Ctrl+D to exit)\n", device_name);
    
    int pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd == -1) {
        fprintf(stderr, "[C-Shark] Could not get pcap file descriptor.\n");
        pcap_close(handle); 
        return 0;
    }
    
    int exit_status = 0;

    while (!g_stop_sniffing) {
        // select() loop
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(pcap_fd, &read_fds);

        int activity = select(pcap_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0) {
            if (errno == EINTR) {
                // Interrupted by signal (likely Ctrl+C)
                if (g_stop_sniffing) {
                    break; // graceful stop
                }
                continue; // spurious, retry
            }
            perror("[C-Shark] select() error");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char buf[1];
            if (read(STDIN_FILENO, buf, sizeof(buf)) == 0) {
                printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
                exit_status = -1;
                break;
            }
        }
        
        if (FD_ISSET(pcap_fd, &read_fds)) {
            pcap_dispatch(handle, -1, parse_packet, NULL);
        }
    }

    // NEW: Free the compiled filter program's memory
    if (filter_exp != NULL) {
        pcap_freecode(&fp);
    }

    pcap_close(handle);
    if (g_stop_sniffing) {
        printf("\n[C-Shark] Capture stopped.\n");
    }
    return exit_status;
}

int list_devices() {
    pcap_if_t *all_devices, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 1;

    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }

    printf("[C-Shark] Searching for available interfaces... Found!\n\n");

    for (device = all_devices; device != NULL; device = device->next) {
        printf("%d. %s", count, device->name);
        if (device->description) {
            printf(" (%s)\n", device->description);
        } else {
            printf(" (No description available)\n");
        }
        count++;
    }

    pcap_freealldevs(all_devices);
    return count - 1;
}

