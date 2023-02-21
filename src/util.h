#pragma once
#include <stdint.h>
#include <net/if.h>

struct InterfaceInfo {
  char name[IFNAMSIZ];
  int index;
  uint8_t mac[6];
  uint32_t ip;
};

struct IPInfo {
  char *ip_str;
  uint32_t ip;
  uint8_t mac[6];
};

struct cmdflags {
  volatile int restore;
  volatile int respond;
};

// Get IPv4 address of an interface
// Returns the IPv4 Address (non-zero) of the interface on success
// Returns 0 on failure
// [Arguments]
// interface = Name of Interface
uint8_t util_get_if_ip(const char *interface, uint32_t *out);

// Get MAC/Hardware address of an interface
// Returns 1 on success
// Returns 0 on failure
// [Arguments]
// interface = Name of Interface
// out = Pointer to array to write MAC address to
uint8_t util_get_if_mac(const char *interface, uint8_t out[6]);

// Get index of interface
// Returns the index of the interface on success
// Returns -1 on failure
// [Arguments]
// interface = Name of Interface
int util_get_if_index(const char *interface);

void util_print_mac(const uint8_t mac[6]);

// Checks if IPv4 forwarding (/proc/sys/net/ipv4/ip_forward) is enabled on this system
// Returns 1 when ip forwarding is enabled
// Returns 0 when it is not enabled, or on error
uint8_t util_ipforward_enabled();

// Parse an IPv4 address
// Returns 1 on success
// Returns 0 on failure
uint8_t util_parse_ip(const char *ip, uint32_t *out);

void util_usage(char *cmd);
uint8_t util_parse_opts(int argc, char *argv[], struct InterfaceInfo *interface, struct IPInfo *victim, struct IPInfo *target, struct cmdflags *flags);
uint8_t util_get_if_info(struct InterfaceInfo *interface);
