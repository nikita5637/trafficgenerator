/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "packet.h"

#define BUF_SIZ								1024
#define DELAY_BETWEEN_SENDING_PACKETS_USEC	1000000
#define DESTINATION_ADDRESSES_TABLE_SIZE 4
#define SLEEP_TIME_USEC						100000

#define ENABLE_THREAD(id, if_name, thread) \
	threads_number++; \
	thread_id = id; \
	iface_name = if_name; \
	pthread_create(&thread##id, NULL, (void *) thread, NULL); \
	usleep(SLEEP_TIME_USEC); \
	while (lock) {}

/*#define ENABLE_THREAD0*/
/*#define ENABLE_THREAD1*/
/*#define ENABLE_THREAD2*/
/*#define ENABLE_THREAD3*/

unsigned char destination_addresses_table[DESTINATION_ADDRESSES_TABLE_SIZE][6];
unsigned int count_addresses_in_table = 0;
volatile bool lock = false;
volatile bool sending_packet = false;
unsigned int thread_id = 1;
char * iface_name;

char data[] = {0x08, 0x06,  /*ARP*/ /*13*/ 
				0x00, 0x01,  /*Ethernet*/ /*15*/ 
				0x08, 0x00, /*IP*/ /*17*/ 
				0x06,  /*HW size*/ /*19*/ 
				0x04,  /*Protocol size*/ /*20*/ 
				0x00, 0x01,  /*Opcode*/ /*21*/ 
				0x00, 0x1b, 0x21, 0xa6, 0x92, 0x2e, /*source mac*/ /*23*/ 
				0xc0, 0xa8, 0x38, 0x66,   /*source ip*/ /*29*/ 
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   /*destination mac*/ /*33*/ 
				0xc0, 0xa8, 0xc8, 0x01,   /*destination ip*/ /*39*/ 
				};

void * thread(void) {
	lock = true;

    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len = 0;
    char sendbuf[BUF_SIZ];
	/*struct ether_header *eh = (struct ether_header *) sendbuf;*/
	struct Packet *packet = (struct Packet *) sendbuf;
    struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    struct sockaddr_ll socket_address;
	const unsigned int threadid = thread_id;
    char ifName[IFNAMSIZ];

	strncpy(ifName, iface_name, IFNAMSIZ - 1);

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("socket");
    }

    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");

	/* Init skeleton of packet */
    memset(sendbuf, 0, BUF_SIZ);
	packet_init(packet);


    /* Ethernet header */
	SET_MAC_ADDRESS_AS_CUSTOM(packet->eth.ether_shost, (uint8_t *)&if_mac.ifr_hwaddr.sa_data);

	destination_addresses_table[threadid][0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	destination_addresses_table[threadid][1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	destination_addresses_table[threadid][2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	destination_addresses_table[threadid][3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	destination_addresses_table[threadid][4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	destination_addresses_table[threadid][5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];

	printf("Threadid: %d\t Ifname: %s\n", threadid, ifName);

    /* Ethertype field */
    /*eh->ether_type = htons(ETH_P_IP);*/

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;

	lock = false;

	while (1) {
		if (!sending_packet)
			continue;

		tx_len = sizeof(struct ether_header);

		/* Destination MAC */
		SET_MAC_ADDRESS_AS_CUSTOM(socket_address.sll_addr, dst_eth_addr);

		for (int i = tx_len; i < sizeof(struct Packet); i++) {
			/*sendbuf[i] = (char)(void *)packet[i];*/
		}

		if (sendto(sockfd, sendbuf, sizeof(struct Packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");
		else
			/*
			 *printf("Threadid: %d Sending to: %02X:%02X:%02X:%02X:%02X:%02X\n", \
			 *    threadid, \
			 *    socket_address.sll_addr[0], \
			 *    socket_address.sll_addr[1], \
			 *    socket_address.sll_addr[2], \
			 *    socket_address.sll_addr[3], \
			 *    socket_address.sll_addr[4], \
			 *    socket_address.sll_addr[5] \
			 *);
			 */
		usleep(DELAY_BETWEEN_SENDING_PACKETS_USEC + rand() % 1000);
	}
}

int main(int argc, char *argv[])
{
	int i = 0;
	srand(time(NULL));

	pthread_t thread0;
	pthread_t thread1;
	pthread_t thread2;
	pthread_t thread3;
	uint8_t threads_number;

ENABLE_THREAD(0, "vmnet1", thread);
/*ENABLE_THREAD(1, "vmnet3", thread);*/
/*ENABLE_THREAD(2, "vmnet4", thread);*/
/*ENABLE_THREAD(3, "vmnet5", thread);*/


	printf("TABLE\n");
	for (i = 0; i < 4; i++) {
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", \
				destination_addresses_table[i][0], \
				destination_addresses_table[i][1], \
				destination_addresses_table[i][2], \
				destination_addresses_table[i][3], \
				destination_addresses_table[i][4], \
				destination_addresses_table[i][5]);
	}

	/* Enable sending packets */
	sending_packet = true;

	while (1) {}

    return 0;
}
