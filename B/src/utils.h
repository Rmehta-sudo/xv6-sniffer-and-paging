// src/utils.h

#ifndef UTILS_H
#define UTILS_H

#include <signal.h> // For sig_atomic_t

// The global handle is no longer needed here
extern volatile sig_atomic_t g_stop_sniffing;

void setup_signal_handler();

#endif // UTILS_H