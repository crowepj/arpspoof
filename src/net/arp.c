#include "arp.h"

#include <arpa/inet.h>
#include <string.h>

ArpPacket arp_new(uint16_t oper, const uint8_t* sha, uint32_t spa, const uint8_t* tha, uint32_t tpa) {
  ArpPacket ret;
  memcpy(ret.ethheader.h_source, sha, ETH_ALEN);
  memcpy(ret.ethheader.h_dest, tha, ETH_ALEN);
  ret.ethheader.h_proto = htons(ETH_P_ARP);

  // Hardware and Protocol Type
  ret.htype = htons(HTYPE_ETH);
  ret.ptype = htons(ETH_P_IP);

  // Hardware and Protocol Address Length
  ret.hlen = ETH_ALEN;
  ret.plen = PLEN_IPV4;

  // Operation
  ret.oper = htons(oper);

  // Copy sender and target MAC/Hardware Address
  memcpy(ret.sha, sha, ETH_ALEN);
  memcpy(ret.tha, tha, ETH_ALEN);

  // Target and Sender protocol (IP) Addresses
  ret.spa = spa;
  ret.tpa = tpa;

  return ret;
}
