#include "util.h"

#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t util_get_if_ip(const char *interface, uint32_t *out) {
  if (interface == NULL)
    return 0;

  struct ifreq ifr;
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);

  int s = socket(AF_INET, SOCK_STREAM, 0);

  // Request the IPv4 (AF_INET) address
  ifr.ifr_addr.sa_family = AF_INET;

  // Use ioctl to request the IP address
  if (ioctl(s, SIOCGIFADDR, &ifr) == -1) {
    return 0;
  }

  // Take protocol address out of ifreq data structure
  uint32_t ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
  *out = ip;
  
  return 1;
}

uint8_t util_get_if_mac(const char *interface, uint8_t out[6]) {
  // Fail if interface name is null, or if out array is null
  if (out == NULL || interface == NULL)
    return 0;

  struct ifreq ifr;
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);

  int s = socket(AF_INET, SOCK_STREAM, 0);

  // Use ioctl to request the IP address
  if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
    return 0;
  }

  // Take hardware address out of ifreq data structure
  memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
  return 1;
}

int util_get_if_index(const char *interface) {
  // Fail if interface name is null
  if (interface == NULL)
    return 0;

  struct ifreq ifr;
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);

  int s = socket(AF_INET, SOCK_STREAM, 0);

  // Use ioctl to request the IP address
  if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
    return -1;
  }

  int index = ifr.ifr_ifindex;
  return index;
}

void util_print_mac(const uint8_t mac[6]) {
  printf("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

uint8_t util_ipforward_enabled() {
  FILE* f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
  char c = getc(f);
  fclose(f);

  if (c == '1') {
    return 1;
  }

  else {
    return 0;
  }
}

uint8_t util_parse_ip(const char *ip, uint32_t *out) {
  struct in_addr addr;
  if (inet_aton(ip, &addr) == 0)
    return 0;

  *out = addr.s_addr;
  return 1;
}

void util_usage(char *cmd) {
  printf("Usage: %s [-dDh] -i [Network Interface] -v [Victim I.P] -t <Spoofed I.P>\n", cmd);
}

void help(char *cmd) {
  util_usage(cmd);
  printf("Performs an ARP-spoofing/ARP-cache poisoning attack.\n\nRequired Arguments:\n");
  printf("\t-t : The I.P. Address to spoof as\n\n");
  printf("Optional Arguments:\n");
  printf("\t-d : Don't respond to ARP requests for the spoofed I.P. address.\n");
  printf("\t-D : Don't restore poisoned ARP caches before stopping the program.\n");
  printf("\t-h : Show this message.\n");
  printf("\t-i [Network Interface] : The network interface to spoof on. If not specified, a default interface with the following will be chosen: an interface that is not loopback, is up, and has been assigned an I.P. address.\n");
  printf("\t-v [Victim I.P.] : The victim whose ARP cache will be poisoned. If not specified, the ARP cache of all machines on the network will be poisoned.\n");
}

uint8_t util_parse_opts(int argc, char *argv[], struct InterfaceInfo *interface, struct IPInfo *victim, struct IPInfo *target, struct cmdflags *flags) {
  // Parse command line args
  char c;
  while ((c = getopt(argc, argv, "dDt:v:i:h")) != -1) {
    switch (c) {
      // Don't respond to ARP requests for the spoofed ip
    case 'd':
      flags->respond = 0;
      break;

      // Don't restore the ARP cache after poisoning
    case 'D':
      flags->restore = 0;
      break;

      // The IP to spoof
    case 't':
      target->ip_str = optarg;
      break;

      // The victim's IP - if left blank, broadcast
    case 'v':
      victim->ip_str = optarg;
      break;

      // The interface to spoof on - if left blank, a default one is chosen
    case 'i':
      interface->name = optarg;
      break;

      // help flag
    case 'h':
      help(argv[0]);
      exit(EXIT_SUCCESS);
      break;

    case '?':
    case ':':
      return 0;
      break;
    }
  }

  return 1;
}

uint8_t util_get_if_info(struct InterfaceInfo *interface) {
  if (!util_get_if_ip(interface->name, &interface->ip)) {
    perror("Failed to get interface IP... exiting.\n\t");
    return 0;
  }

  if (!util_get_if_mac(interface->name, interface->mac)) {
    perror("Failed to get interface MAC address... exiting.\n\t");
    return 0;
  }

  if ((interface->index = util_get_if_index(interface->name)) == -1) {
    perror("Failed to get interface index... exiting.\n\t");
    return 0;
  }

  return 1;
}
