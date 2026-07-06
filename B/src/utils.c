// src/utils.c

#include "utils.h"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

// NEW: A flag for our custom sniffing loop.
// volatile sig_atomic_t is safe to use in signal handlers.
volatile sig_atomic_t g_stop_sniffing = 0;

void signal_handler(int signum) {
    if (signum == SIGINT) {
        // Instead of breaking a pcap_loop, just set our flag.
        g_stop_sniffing = 1;
    }
}

void setup_signal_handler() {
    signal(SIGINT, signal_handler);
}