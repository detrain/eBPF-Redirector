#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#define EXIT_FAILURE -1;


/*
* Description: Parses ethernet header
* Parameters: ptr to beginning of frame, pointer to end of data, ptr to ethernet header struct
* Returns: `int`, ether type (in big endian)
*/
static __always_inline int parse_ethhdr(void** dataCursor, void *dataEnd, struct ethhdr **ethhdr)
{
	struct ethhdr* ethernetHeader = *dataCursor;
	int hdrsize = sizeof(*ethernetHeader);

	if (*dataCursor + hdrsize > dataEnd)
		return EXIT_FAILURE;

	*dataCursor += hdrsize;
	*ethhdr = ethernetHeader;

	return ethernetHeader->h_proto;
}


/*
* Description: Parses IPv4 header
* Parameters: ptr to beginning of packet, pointer to end of data, ptr to iphdr header struct
* Returns: `int`, the ip protocol (in big endian)
*/
static __always_inline int parse_ipv4hdr(void** dataCursor, void *dataEnd, struct iphdr **ipv4hdr)
{
	struct iphdr* ipv4Header = *dataCursor;

	if ( *dataCursor + 1 > dataEnd)
		return EXIT_FAILURE;

	int hdrsize = ipv4Header->ihl * 4;

	if ( *dataCursor + hdrsize > dataEnd )
		return EXIT_FAILURE;

	*dataCursor += hdrsize;
	*ipv4hdr = ipv4Header;

	return ipv4Header->protocol;
}


/*
* Description: Parses TCP header
* Parameters: ptr struct, ptr end of data, ptr empty tcphdr
* Returns: `int`, tcp header size
*/
static __always_inline int parse_tcphdr(void **dataCursor, void *data_end, struct tcphdr **tcphdr)
{
	struct tcphdr *tcpHeader = *dataCursor;
	int hdrsize;

	if (tcpHeader + 1 > data_end)
		return -1;

	hdrsize = h->doff * 4;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if ( *dataCursor + hdrsize > data_end)
		return -1;

	dataCursor += hdrsize;
	*tcphdr = tcpHeader;

	return hdrsize;
}


/*
* Description: Parses ICMP header
* Parameters: ptr struct, ptr end of data, ptr empty icmphdr
* Returns: `int`, icmp type
*/
static __always_inline int parse_icmphdr(void** dataCursor, void *dataEnd, struct icmphdr **icmphdr)
{
	struct icmphdr *icmpHeader = *dataCursor;

	if ( *dataCursor + sizeof(icmphdr) > dataEnd )
		return EXIT_FAILURE;

	*dataCursor += sizeof(icmphdr);
	*icmphdr = icmpHeader;

	return icmpHeader->type;
}