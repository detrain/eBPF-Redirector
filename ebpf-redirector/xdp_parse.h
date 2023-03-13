#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#define EXIT_FAILURE -1;
#define MAX_PACKET_OFFSET 0xffff

struct Cursor
{
	void* position;
};


/*
* Description: Parses ethernet header
* Parameters: ptr to beginning of frame, pointer to end of data, ptr to ethernet header struct
* Returns: `int`, ether type (in big endian)
*/
static __always_inline int parse_ethhdr(struct Cursor* dataCursor, void *dataEnd, struct ethhdr **ethhdr)
{
	struct ethhdr* ethernetHeader = dataCursor->position;
	int hdrsize = sizeof(*ethernetHeader);

	if (dataCursor->position + hdrsize > dataEnd)
		return EXIT_FAILURE;

	dataCursor->position += hdrsize;
	*ethhdr = ethernetHeader;

	return ethernetHeader->h_proto;
}


/*
* Description: Parses IPv4 header
* Parameters: ptr to beginning of packet, pointer to end of data, ptr to iphdr header struct
* Returns: `int`, the ip protocol (in big endian)
*/
static __always_inline int parse_ipv4hdr(struct Cursor* dataCursor, void *dataEnd, struct iphdr **ipv4hdr)
{
	struct iphdr* ipv4Header = dataCursor->position;
	int hdrsize;

	if ( dataCursor->position + 1 >= dataEnd)
		return EXIT_FAILURE;

	hdrsize = ipv4Header->ihl * 4;

	if ( ((int)(size_t)(dataCursor->position + hdrsize)) > MAX_PACKET_OFFSET )
		return EXIT_FAILURE;

	if ( dataCursor->position + hdrsize > dataEnd )
		return EXIT_FAILURE;

	*ipv4hdr = ipv4Header;
	dataCursor->position += hdrsize;
	
	return ipv4Header->protocol;
}


/*
* Description: Parses TCP header
* Parameters: ptr struct, ptr end of data, ptr empty tcphdr
* Returns: `int`, tcp header size
*/
static __always_inline int parse_tcphdr(struct Cursor* dataCursor, void *data_end, struct tcphdr **tcphdr)
{
	struct tcphdr *tcpHeader = dataCursor->position;
	int hdrsize;

	if ( dataCursor->position + 1 > data_end)
		return -1;

	hdrsize = tcpHeader->doff * 4;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if ( dataCursor->position + hdrsize > data_end)
		return -1;

	dataCursor->position += hdrsize;
	*tcphdr = tcpHeader;

	return hdrsize;
}


/*
* Description: Parses ICMP header
* Parameters: ptr struct, ptr end of data, ptr empty icmphdr
* Returns: `int`, icmp type
*/
static __always_inline int parse_icmphdr(struct Cursor* dataCursor, void *dataEnd, struct icmphdr **icmphdr)
{
	struct icmphdr *icmpHeader = dataCursor->position;

	if ( dataCursor->position + sizeof(icmphdr) > dataEnd )
		return EXIT_FAILURE;

	dataCursor->position += sizeof(icmphdr);
	*icmphdr = icmpHeader;

	return icmpHeader->type;
}