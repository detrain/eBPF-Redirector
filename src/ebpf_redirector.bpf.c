
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "parse.h"
#include "redirect.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp_redirect")
int xdp_redirector(struct xdp_md *ctx)
{
    void* data = (void*)(long) ctx->data;
    void* dataEnd = (void*)(long) ctx->data_end;

	void* dataCursor = data; // Track start of each layer as its processed

    struct ethhdr *ethernetHeader;
    struct iphdr *ipv4Header;
    struct icmphdr *icmpHeader;

    int headerType; // Track type of the header, e.g. IPv4, ICMP, ICMP-Type 0
    int action = XDP_PASS;

	headerType = parse_ethhdr(&dataCursor, dataEnd, &ethernetHeader);
    
	if ( bpf_ntohs(headerType) != ETH_P_IP )
		goto xdp_action;

    headerType = parse_ipv4hdr(&dataCursor, dataEnd, &ipv4Header);
   
    if ( bpf_ntohs(headerType) != IPPROTO_ICMP )
        goto xdp_action;

    headerType = parse_icmphdr(&dataCursor, dataEnd, &icmpHeader);

    if ( bpf_ntohs(headerType) != ICMP_ECHO)
        goto xdp_action;

    if ( bpf_ntohs(icmpHeader->un.echo.sequence) % 2 == 0 )
    {
        swap_mac_addrs(ethernetHeader);
        action = XDP_REDIRECT;
    }

xdp_action:
	return action;
}
//    bpf_printk("Type = %04X", bpf_ntohs(headerType));
