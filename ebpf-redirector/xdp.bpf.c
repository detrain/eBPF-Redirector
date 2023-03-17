
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_parse.h"
#include "xdp_redirect.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Redirection Ethernet addresses
struct eth_addrs
{
    __u8 atk[ETH_ALEN];
    __u8 srv[ETH_ALEN];
    __u8 tgt[ETH_ALEN];
}

// Redirection IP addresses
struct ip_redir
{
    __be32 atk;
    __be32 srv;
    __be32 tgt;
}


SEC("xdp_redirect")
int xdp_redirector(struct xdp_md *ctx)
{
    void* data = (void*)(long) ctx->data;
    void* dataEnd = (void*)(long) ctx->data_end;

	void* dataCursor; // Track start of each layer as its processed
    
    struct ethhdr *ethernetHeader;
    struct iphdr *ipv4Header;
    struct icmphdr *icmpHeader;

    dataCursor = data;

    int headerType; // Track type of the header, e.g. IPv4, ICMP, ICMP-Type 0
    int action = XDP_PASS;

	headerType = parse_ethhdr(&dataCursor, dataEnd, &ethernetHeader);
    
	if ( bpf_ntohs(headerType) != ETH_P_IP )
		goto xdp_action;

    headerType = parse_ipv4hdr(&dataCursor, dataEnd, &ipv4Header);
   
    if ( headerType != IPPROTO_ICMP )
        goto xdp_action;

    headerType = parse_icmphdr(&dataCursor, dataEnd, &icmpHeader);
    bpf_printk("Type = %04X", headerType);

    if ( headerType != ICMP_ECHO)
        goto xdp_action;
    
    bpf_printk("REACHED ICMP");

    if ( bpf_ntohs(icmpHeader->un.echo.sequence) % 2 == 0 )
    {
        action = XDP_DROP;
    }

xdp_action:
	return action;
}
