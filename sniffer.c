#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>

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
	uint32_t src_ip; // Source IP
	uint32_t dest_ip; // Destination IP
}IP_header;

typedef struct {
	uint8_t dest_mac[6]; // Destination MAC address
	uint8_t src_mac[6]; // Source MAC address
	uint16_t type; // Protocol type
}Ethernet_header;

typedef struct {
	uint8_t type;
	uint8_t matricula[8];
	uint16_t tamanho;
	char *nome;
}Msg;

void sniff(unsigned char *buffer, int data_size){
	Ethernet_header *eth = (Ethernet_header *)buffer;

	if(ntohs(eth->type) == ETH_P_IP){
		IP_header *ip = (IP_header *)(eth + 1);

		if(ntohs(ip->protocol) == IPPROTO_UDP){
			UDP_header *udp = (UDP_header *)(ip + 1);

			if(ntohs(udp->dest_port) == 1234){
				Msg *msg = (Msg *)(udp + 1);

				// printf("MAC de origem: %u\n", ntohs(eth->src_mac));
				// printf("MAC de destino: %u\n", ntohs(eth->dest_mac));
				// printf("IP de origem: %u\n", ntohs(ip->src_ip));
				// printf("IP de destino: %u\n", ntohs(ip->dest_ip));
				// printf("Protocolo de transporte: %u\n", ntohs(ip->protocol));
				// printf("Porta UDP de origem: %s\n", ntohs(udp->src_port));
				// printf("Porta UDP de destino: %s\n", ntohs(udp->dest_port));

				if(msg->type == 1){
					printf("Matricula: ");
					for(int i = 0; i < 8; i++){
						printf("%u", msg->matricula[i]);
					}
				}else if(msg->type == 2){

				}
			}
		}
	}
}

int main(){

	// Strcuture to store the sending address
	struct sockaddr socket_addr;

	unsigned char *buffer = (unsigned char *) malloc(UINT_MAX);

	int socket_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // Receive raw packets from all protocols

	if(socket_raw < 0){
		printf("[ERROR] - Socket\n");
		return 1;
	}

	while(1){
		int socket_addr_size = sizeof(socket_addr);

		// Receiving data from socket and storing on buffer
		int data_size = recvfrom(socket_raw, buffer, UINT_MAX, 0, &socket_addr, &socket_addr_size);

		if(data_size < 0){
			printf("[ERROR] - Receiving packet\n");
			return 1;
		}

		sniff(buffer, data_size);
	}
	
	return 0;
}