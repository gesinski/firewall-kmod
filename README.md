# Linux Kernel Firewall Module (Netfilter)

## Overview

This project implements a **simple firewall as a Linux kernel module** using the **Netfilter framework**.  
The module inspects incoming IPv4 packets and applies basic security rules, including:

- IP spoofing detection
- Fragmented packet filtering
- ICMP filtering
- UDP traffic restriction
- TCP scan detection
- ACK-based scan mitigation using conntrack

The firewall is implemented as a kernel module and hooks into the
`NF_INET_PRE_ROUTING` Netfilter hook.

The 
---

## Features

### IP Filtering
- Drops packets from reserved or invalid source address ranges:
  - `127.0.0.0/8`
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `224.0.0.0/4`
  - `255.255.255.255`

### Fragmentation Protection
- Drops all fragmented IPv4 packets (`MF` flag or fragment offset set)

### ICMP Filtering
- Drops ICMP Echo Requests (ping)
- Allows other ICMP messages

### UDP Filtering
- Allows only DNS traffic (UDP port 53)
- Drops all other UDP packets

### TCP Inspection
TCP packets are analyzed using `tcp_flag_word()`:

- Detects and drops:
  - NULL scans
  - SYN+FIN scans
  - SYN+RST scans
  - Xmas scans (FIN+PSH+URG)
- Detects **ACK-only scans** and drops them **unless they belong to an established connection**

Connection validation is performed using **nf_conntrack**.

---

## ACK Scan Handling

ACK-only packets are checked using Linux connection tracking:

- If the packet belongs to an established connection (`IPS_CONFIRMED`) → ACCEPT
- Otherwise → DROP and log as suspicious

This approach prevents ACK-based reconnaissance scans while allowing legitimate traffic.

---

## Limitations (Important)

Due to Linux TCP input validation, **malformed TCP packets** (NULL, FIN, Xmas scans)  
are **dropped by the kernel TCP stack before reaching Netfilter hooks**.

As a result:
- These packets may **not always be visible** in `NF_INET_PRE_ROUTING`
- ACK-only scans remain detectable because they use valid TCP semantics

This behavior is expected and documented in the Linux networking stack.

---

## Build & Usage

### Build
```
make
```

### Load module
```
sudo insmod firewall.ko
```

### Unload module
```
sudo rmmod firewall
```

### View logs
```
dmesg -w
```

## Testing 

```
ping <FIREWALL_IP> 
ping <HOST_IP>
echo "test" | nc -u <FIREWALL_IP> 23 #udp test 53 -> works
dig google.com
sudo nc -l -p 8080          # on firewall machine
nc -v <FIREWALL_IP> 8080    # host to check connections
sudo nping --tcp --flags fin,psh,urg -p 8080 <FIREWALL_IP> # Xmas scan
sudo nping --tcp --flags none -p 8080 <FIREWALL_IP>      # NULL scan
sudo nping --tcp --flags fin -p 8080  <FIREWALL_IP>      # fin scan
ping -s 2000 -M want <FIREWALL_IP>  #fragmented ping
nmap -f <FIREWALL_IP>       # fragmeneted tcp packet
```

## Acknowledgements

The foundational structure of this project, including the use of Netfilter hooks in a Linux kernel module, was based on the article:

**“Linux Kernel Communication — Part 1: Netfilter Hooks”**  
Infosec Writeups  
https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e

Concepts such as registering a Netfilter hook and basic packet inspection logic were inspired by that resource.
