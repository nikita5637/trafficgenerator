#ifndef PACKET_H
#define PACKET_H

#include <net/ethernet.h>
#include <netinet/ip.h>

/*#define ARP*/
#define TCPUDP
#define TCP
/*#define UDP*/
struct Packet {
	struct ether_header eth;

	struct ip ip;

};

/*struct Packet packet;*/

#ifdef TCPUDP
void packet_init(struct Packet * packet) {
	memset(packet->eth.ether_dhost, 0xFF, sizeof(uint8_t) * ETH_ALEN);

	packet->eth.ether_type = 0x0806;

	packet->ip.ip_v = 0x4;
	packet->ip.ip_hl = 0x4;
	packet->ip.ip_tos = 0x0;
	packet->ip.ip_id = 0x0;
	packet->ip.ip_off = 0x0;
	packet->ip.ip_ttl = 0x40;
#ifdef TCP
	packet->ip.ip_p = 0x6;
#endif /* TCP */
#ifdef UDP
	packet->ip.ip_p = 0x11;
#endif /* UDP */

	packet->ip.ip_sum = 0x0;

#define SRC1 105
#define SRC2 105
#define SRC3 105
#define SRC4 105
	packet->ip.ip_src.s_addr = (SRC1 << 24) + (SRC2 << 16) + (SRC3 << 8) + (SRC4);

#define DST1 105
#define DST2 105
#define DST3 105
#define DST4 105
	packet->ip.ip_dst.s_addr = (DST1 << 24) + (DST2 << 16) + (DST3 << 8) + (DST4);

}
#endif /* TCPUDP */

#endif /* PACKET_H */
