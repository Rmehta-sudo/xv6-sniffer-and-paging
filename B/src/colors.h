#ifndef COLORS_H
#define COLORS_H

// Resets all text attributes
#define C_RESET   "\033[0m"

// Text Styles
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"

// Colors for different layers
#define C_PKT_HDR "\033[1;33m" // Bold Yellow for Packet Header
#define C_L2      "\033[1;36m" // Bold Cyan for Layer 2
#define C_L3      "\033[0;32m" // Green for Layer 3
#define C_L4      "\033[0;35m" // Purple for Layer 4
#define C_L7      "\033[0;37m" // White for Layer 7 (Payload)
#define C_DATA    "\033[0;90m" // Bright Black (Gray) for payload hex

#endif //COLORS_H