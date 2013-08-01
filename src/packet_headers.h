#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
/********** JB ***********/
#include <netinet/ip6.h>         
#ifdef linux
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <netinet/tcp.h>

#ifdef linux
struct icmphdr {
	uint8_t type;                /* message type */
	uint8_t code;                /* type sub-code */
	uint16_t checksum;
	union
	{
		struct {
			uint16_t id;
			uint16_t sequence;
		}
		echo;                     /* echo datagram */
		uint32_t   gateway;        /* gateway address */
		struct {
			uint16_t unused;
			uint16_t mtu;
		}
		frag;                     /* path mtu discovery */
	} un;
};
#else
#include <netinet/ip_icmp.h>
#endif

#define IPv6	6
#define IPv4	4
/* locate header positions and structures */

/* this is in net/ethernet.h */
/* #define ETHER_HDR_LEN		sizeof(struct ether_header) */

#define ETHERNET(packet)    ((struct ether_header *)packet)
#define IPV(packet)         (((*(packet+ETHER_HDR_LEN) & 0xf0) == 0x60) ? IPv6: IPv4)

#define IP(packet)          ((struct ip *)(packet+ETHER_HDR_LEN))
#define IP6(packet)         ((struct ip6_hdr *)(packet+ETHER_HDR_LEN)) 

#define IP_HDR_LEN(packet)  (IP(packet)->ip_hl*4)
#define IP6_HDR_LEN	    (40)                   

#define IP6_NXT_HDR(packet) (*(packet+ETHER_HDR_LEN+6))

#define TCP(packet)	    ((struct tcphdr *)(packet+ETHER_HDR_LEN+ \
				((IPV(packet) == 6) ? IP6_HDR_LEN: IP_HDR_LEN(packet))))
#define UDP(packet)	    ((struct udphdr *)(packet+ETHER_HDR_LEN+ \
				((IPV(packet) == 6) ? IP6_HDR_LEN: IP_HDR_LEN(packet))))

/********** old ***********/
//#define TCP(packet)         ((struct tcphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))
//#define UDP(packet)         ((struct udphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))

#endif

 
