#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <string.h>
#include <unistd.h>

#include "src/pcap_handler.h"
#include "src/utils.h"
#include "src/packet_storage.h"
#include "src/packet_parser.h" 
#include "src/inspector.h"


void print_banner() {
    printf("Welcome to C-Shark!\n");
    printf("The LAZY Corp. Command-Line Packet Predator\n");
    printf("==============================================\n");
}

void print_menu(const char *dev_name) {
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", dev_name);
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n\n");
    printf("Enter your choice: ");
}

int handle_filtered_sniffing(char *device_name) {
    char filter_exp[256] = {0}; // Buffer for the filter string
    int choice = 0;

    printf("\n--- Filter Selection ---\n");
    printf("1. TCP\n");
    printf("2. UDP\n");
    printf("3. ARP\n");
    printf("4. DNS (udp or tcp port 53)\n");
    printf("5. HTTP (tcp port 80)\n");
    printf("6. HTTPS (tcp port 443)\n");
    printf("0. Back to Main Menu\n");
    printf("Enter filter choice: ");

    int scanr = scanf("%d", &choice);
    if (scanr != 1) {
        if (scanr == EOF) {
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            return -1; // Signal app exit
        }
        // Clear buffer on invalid input
        while(getchar() != '\n');
        return 0; // Go back to menu
    }

    switch (choice) {
        case 1: strcpy(filter_exp, "tcp"); break;
        case 2: strcpy(filter_exp, "udp"); break;
        case 3: strcpy(filter_exp, "arp"); break;
        case 4: strcpy(filter_exp, "udp port 53 or tcp port 53"); break; // DNS over UDP or TCP
        case 5: strcpy(filter_exp, "tcp port 80"); break;
        case 6: strcpy(filter_exp, "tcp port 443"); break;
        case 0: return 0; // Go back to menu
        default:
            printf("Invalid filter choice.\n");
            return 0; // Go back to menu
    }
    
    // Free storage and reset counter before starting a new session.
    free_packet_storage();
    reset_packet_counter(); // <-- ADDED
    
    // Call start_sniffing with the selected filter and return its exit status
    return start_sniffing(device_name, filter_exp);
}


int main() {
    pcap_if_t *all_devs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int dev_count = 0;
    int choice = 0;

    setup_signal_handler();
    print_banner();

    dev_count = list_devices();
    if (dev_count <= 0) return 1;

    printf("\nSelect an interface to sniff (1-%d): ", dev_count);
    int scanr = scanf("%d", &choice);
    if (scanr != 1 || choice < 1 || choice > dev_count) {
        if (scanr == EOF) {
            printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
            return 0;
        }
        fprintf(stderr, "Invalid selection.\n");
        return 1;
    }

    pcap_findalldevs(&all_devs, errbuf);
    dev = all_devs;
    for (int i = 1; i < choice; i++) {
        dev = dev->next;
    }
    char *chosen_dev = dev->name;

int keep_running = 1;
    while (keep_running) {
        print_menu(chosen_dev);
        int menu_choice;

        int scanf_result = scanf("%d", &menu_choice);
        if (scanf_result != 1) {
            if (scanf_result == EOF) { 
                printf("\n[C-Shark] Ctrl+D detected. Exiting.\n");
                break; 
            }
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n');
            continue;
        }

        switch (menu_choice) {
            case 1:
                free_packet_storage();
                reset_packet_counter();
                if (start_sniffing(chosen_dev, NULL) == -1) {
                    keep_running = 0;
                }
                break;
            case 2:
                if (handle_filtered_sniffing(chosen_dev) == -1) {
                    keep_running = 0;
                }
                break;
            case 3:
                // MODIFIED: Call the new inspector function
                inspect_session();
                break;
            case 4:
                keep_running = 0;
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                while (getchar() != '\n');
                break;
        }
    }

    printf("\n[C-Shark] Mission complete. Swimming away.\n");
    free_packet_storage();
    pcap_freealldevs(all_devs);
    return 0;
}