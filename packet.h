#ifndef PACKET_H
#define PACKET_H

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SET_MAC_ADDRESS_AS_BROADCAST(addr) \
	memset(addr, 0xFF, sizeof(uint8_t) * ETH_ALEN);

#define SET_MAC_ADDRESS_AS_NULL(addr) \
	memset(addr, 0x00, sizeof(uint8_t) * ETH_ALEN);

#define SET_MAC_ADDRESS_AS_CUSTOM(addr_to, addr_from) \
	memcpy((void *) addr_to, (const void *) addr_from, sizeof(uint8_t) * ETH_ALEN);

/*#define ARP*/

#define TCPUDP
#define TCP
/*#define UDP*/

struct Packet {
	/* 14 bytes Ethernet */
	struct ether_header eth;

#ifdef ARP

#endif /* ARP */

#ifdef TCPUDP

	struct ip ip;
#ifdef TCP
	struct tcphdr tcp;
	uint8_t options[12]; /* unused */
	uint8_t payload[9];
#endif /* TCP */

#ifdef UDP

#endif /* UDP */
#endif /* TCPUDP */
} __attribute__ ((__packed__));



void packet_init(struct Packet *packet);

/* Skeleton for ARP packets */
#ifdef ARP
void packet_init(struct Packet *packet) {
	SET_MAC_ADDRESS_AS_BROADCAST(packet->eth.ether_dhost);

	packet->eth.ether_type = htons(ETH_P_ARP);
}
#endif /* ARP */



/* Skeleton for TCP/UDP packets */
#ifdef TCPUDP

#define SRC1 105
#define SRC2 105
#define SRC3 105
#define SRC4 105
#define DST1 192
#define DST2 168
#define DST3 56
#define DST4 128
#define SRCPORT 65417
#define DSTPORT 52368

uint8_t dst_eth_addr[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x9f, 0x51, 0xbe};
uint8_t payload[9] = "DEADTEST";
unsigned int src_addr = (SRC1 << 24) + (SRC2 << 16) + (SRC3 << 8) + (SRC4);
unsigned int dst_addr = (DST1 << 24) + (DST2 << 16) + (DST3 << 8) + (DST4);

void packet_init(struct Packet *packet) {
	SET_MAC_ADDRESS_AS_CUSTOM(packet->eth.ether_dhost, dst_eth_addr);

	packet->eth.ether_type = htons(ETH_P_IP);

#ifdef TCP
	/* IP FIELDS */
	packet->ip.ip_v = 0x4;
	packet->ip.ip_hl = 0x5;
	packet->ip.ip_tos = 0x00;
	packet->ip.ip_len = htons(0x003D);
	packet->ip.ip_id = htons(0x0001);
	packet->ip.ip_off = htons(0x4000);
	packet->ip.ip_ttl = 0x40;
	packet->ip.ip_p = 0x6;
	packet->ip.ip_sum = 0x72AF;
	packet->ip.ip_src.s_addr = htonl(src_addr);

	packet->ip.ip_dst.s_addr = htonl(dst_addr);

	/* TCP FIELDS */
	packet->tcp.th_sport = htons(SRCPORT);
	packet->tcp.th_dport = htons(DSTPORT);
	packet->tcp.th_seq = 0xe36a2b0d;
	packet->tcp.th_ack = 0xe997abc4;
	packet->tcp.th_x2 = 0x0;
	packet->tcp.th_off = 0x8;
	packet->tcp.th_flags = TH_ACK;
	packet->tcp.th_win = htons(0x00eb);
	packet->tcp.th_sum = htons(0x5c89);
	packet->tcp.th_urp = 0x0;
	
	packet->options[0] = 0x01;
	packet->options[1] = 0x01;
	packet->options[2] = 0x08;
	packet->options[3] = 0x0a;
	packet->options[4] = 0x00;
	packet->options[5] = 0x36;
	packet->options[6] = 0xfc;
	packet->options[7] = 0xe8;
	packet->options[8] = 0xe8;
	packet->options[9] = 0xe8;
	packet->options[10] = 0xe8;
	packet->options[11] = 0xe8;
	memcpy(packet->payload, payload, sizeof(payload));
#endif /* TCP */

#ifdef UDP
	packet->ip.ip_p = 0x11;
#endif /* UDP */
}
#endif /* TCPUDP */

#endif /* PACKET_H */
