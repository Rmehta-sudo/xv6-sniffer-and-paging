#ifndef PCAP_HANDLER_H
#define PCAP_HANDLER_H

#include <pcap.h>

extern pcap_t *handle;


int start_sniffing(char *device_name, const char *filter_exp);

int list_devices();

#endif // PCAP_HANDLER_H