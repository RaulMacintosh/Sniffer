#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>

#define ETH_P_ALL 0x0003
#define ETH_P_IP 0x0800

typedef struct {
	uint16_t src_port; // Source port
	uint16_t dest_port; // Destination port
	uint16_t length;
	uint16_t checksum;
}UDP_header;

typedef struct {
	uint8_t v_hl; // Version and Header Length
	uint8_t tos; // Type of Service
	uint16_t tl; // Total length
	uint16_t id; // Identification
	uint16_t offset; // Fragment offset
	uint8_t ttl; // Time to live
	uint8_t protocol;
	uint16_t h_checksum; // Header Checksum
	uint8_t src_ip[4]; // Source IP
	uint8_t dest_ip[4]; // Destination IP
}IP_header;

typedef struct {
	uint8_t dest_mac[6]; // Destination MAC address
	uint8_t src_mac[6]; // Source MAC address
	uint16_t type; // Protocol type
}Ethernet_header;

typedef struct {
	uint8_t type;
	uint8_t matricula[8];
	uint8_t tamanho[2];
}Msg;

void sniff(unsigned char *buffer, int data_size){
	Ethernet_header *eth = (Ethernet_header *)buffer;

	if(ntohs(eth->type) == ETH_P_IP){
		IP_header *ip = (IP_header *)(eth + 1);

		if(ip->protocol == IPPROTO_UDP){
			UDP_header *udp = (UDP_header *)(ip + 1);

			if(ntohs(udp->dest_port) == 1234){
				Msg *msg = (Msg *)(udp + 1);

				printf("MAC de origem: %2x:%2x:%2x:%02x:%02x:%02x\n", eth->src_mac[0], eth->src_mac[1],
					eth->src_mac[2],eth->src_mac[3],eth->src_mac[4],eth->src_mac[5]);
				printf("MAC de destino: %2x:%2x:%2x:%02x:%02x:%02x\n", eth->dest_mac[0], eth->dest_mac[1],
					eth->dest_mac[2],eth->dest_mac[3],eth->dest_mac[4],eth->dest_mac[5]);

				printf("IP de origem: %u.%u.%u.%u\n", ip->src_ip[0], ip->src_ip[1], ip->src_ip[2],
					ip->src_ip[3]);
				printf("IP de destino: %u.%u.%u.%u\n", ip->dest_ip[0], ip->dest_ip[1], ip->dest_ip[2],
					ip->dest_ip[3]);

				printf("Protocolo de transporte: %u\n", ip->protocol);
				printf("Porta UDP de origem: %u\n", ntohs(udp->src_port));
				printf("Porta UDP de destino: %u\n", ntohs(udp->dest_port));

				if(msg->type == 1){
					printf("Matricula: \n");
					for(int i = 0; i < 8; i++){
						printf("%c", msg->matricula[i]);
					}
					printf("\n");

					uint16_t msgLength = msg->tamanho[0]*10 + msg->tamanho[1];

					for(char i = 0; i < msgLength; i++){
						printf("%c", *(msg->tamanho + 2 + i));
					}
					printf("\n");

				}else if(msg->type == 2){
					printf("Matricula: \n");
					for(int i = 0; i < 8; i++){
						printf("%c", msg->matricula[i]);
					}
					printf("\n");
				}
			}
		}
	}
}

int main(){

	// Strcuture to store the sending address
	struct sockaddr socket_addr;

	unsigned char *buffer = (unsigned char *) malloc(65534);

	int socket_raw = socket(PF_PACKET, SOCK_RAW, htons(0x0003)); // Receive raw packets from all protocols

	if(socket_raw < 0){
		printf("[ERROR] - Socket\n");
		return 1;
	}

	while(1){
		int socket_addr_size = sizeof(socket_addr);

		// Receiving data from socket and storing on buffer
		int data_size = recvfrom(socket_raw, buffer, 65534, 0, &socket_addr, &socket_addr_size);

		if(data_size < 0){
			printf("[ERROR] - Receiving packet\n");
			return 1;
		}

		sniff(buffer, data_size);
	}
	
	return 0;
}