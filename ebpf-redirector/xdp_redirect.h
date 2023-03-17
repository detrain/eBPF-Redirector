/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
* Description: Swaps ethernet addresses
* Parameters: pointer to ethernet frame
* Returns: void
*/

static __always_inline void swap_mac_addrs(struct ethhdr *etherHeader)
{
	__u8 tmp[ETH_ALEN];

	__builtin_memcpy(tmp, etherHeader->h_source, ETH_ALEN);
	__builtin_memcpy(etherHeader->h_source, etherHeader->h_dest, ETH_ALEN);
	__builtin_memcpy(etherHeader->h_dest, tmp, ETH_ALEN);
}

/*
* Description: Swaps ip addresses
* Parameters: pointer to iphdr
* Returns: void
*/
static __always_inline void swap_ipv4_addrs(struct iphdr *ipHeader)
{
	__be32 tmp = ipHeader->saddr;
	
	ipHeader->saddr = ipHeader->daddr;
	ipHeader->daddr = tmp;
}