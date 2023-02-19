#pragma once
#include <stdint.h>
#include <linux/if_ether.h>

#define HTYPE_ETH 0x1
#define ARP_REQUEST 0x1
#define ARP_REPLY 0x2
#define PLEN_IPV4 0x4
const static uint8_t ARP_BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const static uint8_t ARP_EMPTY[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

typedef struct {
  struct ethhdr ethheader;
  
  // hardware type (htype = 1, ethernet)
  uint16_t htype;

  // protocol type (ptype = 0x0800, IPv4)
  uint16_t ptype;

  // hardware length - length of a hardware address (for ethernet, that is 6 octets)
  uint8_t hlen;

  // protocol length - length of a protocol address (for IPv4, that is 4 octets)
  uint8_t plen;

  // operation (oper = 1 means a request, oper = 2 means a reply)
  uint16_t oper;

  // sender hardware (MAC) address - 6 bytes
  uint8_t sha[ETH_ALEN];

  // sender protocol (IPv4) address - 4 bytes
  uint32_t spa;

  // target hardware (MAC) address - 6 bytes
  uint8_t tha[ETH_ALEN];

  // target protocol (IPv4) address - 4 bytes
  uint32_t tpa;
} __attribute__ ((packed)) ArpPacket;

// Initialise a new Arp Packet
ArpPacket arp_new(uint16_t oper, const uint8_t* sha, uint32_t spa, const uint8_t* tha, uint32_t tpa);

// Resolve an IP to a MAC address using ARP
// sock = raw arp socket
// addr_ll = sockaddr_ll for the interface to send on
// out = array to write result to (on success)
// Returns 0 on failure, 1 on success
//int arp_resolve(int sock, struct sockaddr_ll addr_ll, uint32_t src_ip, uint8_t src_mac[6], uint32_t dest_ip, uint8_t out[6]);
