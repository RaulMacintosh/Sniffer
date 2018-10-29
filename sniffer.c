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
	uint16_t length; // 
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
	uint8_t type; // Mensage type
	uint8_t matricula[8]; // Student ID
	uint8_t tamanho[2]; // Student name length
}Msg;

void sniff(unsigned char *buffer, int data_size){
	Ethernet_header *eth = (Ethernet_header *)buffer; // Fill the ethernet header

	if(ntohs(eth->type) == ETH_P_IP){ // Check if the package type is an IP 
		IP_header *ip = (IP_header *)(eth + 1); // Fill the ip header

		if(ip->protocol == IPPROTO_UDP){ // Check if the content of the package is an UDP datagram
			UDP_header *udp = (UDP_header *)(ip + 1); // Fill the udp header

			if(ntohs(udp->dest_port) == 1234){ // Check if the destination port is the port defined for the student mensage
				Msg *msg = (Msg *)(udp + 1); // Fill the mensage

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

				printf("Tipo da menssagem: %u\n", msg->type);

				printf("Matricula: ");
				for(int i = 0; i < 8; i++){
					printf("%c", msg->matricula[i]);
				}
				printf("\n");

				if(msg->type == 1){
					uint16_t msgLength = 0;
					if(msg->tamanho[0] > 0){
						msgLength = msg->tamanho[0];
						msgLength = msgLength << 8;
					}
					msgLength += msg->tamanho[1]; // The student name length is between 0 and 2^16 

					printf("Tamanho do nome: %u\n", msgLength);
					printf("Nome: ");
					for(uint16_t i = 0; i < msgLength; i++){
						printf("%c", *(msg->tamanho + 2 + i)); // Print the student name that is after the 'tamanho' field
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

	unsigned char *buffer = (unsigned char *) malloc(65575); // Creating a buffer to store the frame

	int socket_raw = socket(PF_PACKET, SOCK_RAW, htons(0x0003)); // Receive raw packets from all protocols

	if(socket_raw < 0){
		printf("[ERROR] - Socket\n");
		return 1;
	}

	while(1){
		int socket_addr_size = sizeof(socket_addr);

		// Receiving data from socket and storing on buffer
		int data_size = recvfrom(socket_raw, buffer, 65575, 0, &socket_addr, &socket_addr_size);

		if(data_size < 0){
			printf("[ERROR] - Receiving packet\n");
			return 1;
		}

		sniff(buffer, data_size);
	}
	
	return 0;
}