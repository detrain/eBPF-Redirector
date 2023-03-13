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

static __always_inline void swap_mac_addrs(struct ethhdr *eth)
{
	__u8 tmpMacAddress[ETH_ALEN];

	__builtin_memcpy(tmpMacAddress, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, tmpMacAddress, ETH_ALEN);
}