#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/*
* Description: Computes ip difference
* Parameters: Takes in pointer to ip header and the ip header size
* Returns: `u16`, new checksum
*/
static __always_inline __u16 ip_checksum(struct iphdr *ipHdr, int ipHdrSize)
{
    unsigned long csum = 0;

    csum = bpf_csum_diff(0, 0, (void *)ipHdr, ipHdrSize, 0);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);

    return ~csum;
}

/*
* Description: Computes tcp checksum difference
* Parameters: 1s complement of old checksum, the new tcp hdr, the old tcp hdr
* Returns: `u16`, new checksum
*/
static __always_inline __u16 tcp_checksum(struct tcphdr *tcpHdr, int tcpHdrSize)
{
    unsigned long csum = 0;

    csum = bpf_csum_diff(0, 0, (void *)tcpHdr, tcpHdrSize, 0);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);

    return ~csum;
}