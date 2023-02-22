# arpspoof
arpspoof is an ARP spoofing utility written in C.

# Platforms
Currently, this project is linux only, but will probably run under WSL (untested).

# Features

- ARP Cache Poisoning


- Responds to ARP requests for spoofed IP addresses (Optional)


- Restores ARP cache before exiting (Optional)


- Option to specify a unicast victim (IP passed to program) or broadcast (entire network/FF:FF:FF:FF:FF:FF MAC Address)

# Usage
arpspoof uses raw sockets. If you do not give it the CAP_NET_RAW capability (method described in Compilation) you will have to run it with `sudo` every time you use `arpspoof`

```
Required Arguments:
	-t : The I.P. Address to spoof as

Optional Arguments:
	-d : Don't respond to ARP requests for the spoofed I.P. address.
	-D : Don't restore poisoned ARP caches before stopping the program.
	-h : Show this message.
	-i [Network Interface] : The network interface to spoof on. If not specified, a default interface with the following will be chosen: an interface that is not loopback, is up, and has been assigned an I.P. address.
	-v [Victim I.P.] : The victim whose ARP cache will be poisoned. If not specified, the ARP cache of all machines on the network will be poisoned.
```
  
The most basic usage of arpspoof might look like this:
  
`arpspoof -t 192.168.0.1`
  
This spoofs as `192.168.0.1` and poisons the ARP cache of all devices on the network

# Compilation
Before compilation, ensure that either `gcc` or `clang` is installed on your system, and that your current working directory is the root folder of this project (the directory with the Makefile).


To compile with `gcc`, run:
`make`

To compile with `clang`, run:
`make CC=clang`

On success, an executable called `arpspoof` will be produced


If you want to use `arpspoof` without `sudo`, you need to give it the CAP_NET_RAW capability:


`sudo setcap CAP_NET_RAW+ep arpspoof`


# TODO
- Stealth mode - Implement an option that doesn't use gratuitous ARP and instead only responds to ARP requests for the spoofed IP


- Option to set custom timeout for ARP resolution


- Option to stop actively spoofing (sending gratuitous packets) after a certain amount of time
