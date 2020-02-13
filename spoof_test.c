#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <time.h>

unsigned short checksum(const void *buffer, int numWords) {
    //Store sum in long, so that carry bits are not lost.
    unsigned long sum = 0;
    const unsigned short *data = buffer;

    for(int i = 0; i < numWords; i++) 
        sum += *data++;
    
    //Adding the carry digits from the csum may produce more carry bits.
    while(sum > 0xFFFF) 
        sum = (sum >> 16) + (sum & 0xFFFF);
    //return the compliment of the sum
    return (unsigned short) ~sum;
}

unsigned char *encapsulateUDP(unsigned char *buffer, int *payloadSize, int dst_port) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, *payloadSize + sizeof(struct udphdr));

    if(!tmp) {
        perror("encapsulateUDP :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(&tmp[sizeof(struct udphdr)], buffer, *payloadSize);

    struct udphdr *udph = (struct udphdr *) tmp;
    udph -> source = htons(rand());
    udph -> dest = htons(dst_port);
    udph -> check = 0; //UDP checksum 0 means checksum unused!
    udph -> len = htons((*payloadSize) + 8);
    *payloadSize += sizeof(struct udphdr);

    return tmp;
}

unsigned char *encapsulateIP(unsigned char *buffer, int *payloadSize, in_addr_t sourceIP, in_addr_t destIP) {
    unsigned char *tmp = NULL;

    tmp = realloc(buffer, (*payloadSize) + sizeof(struct iphdr));

    if(!tmp) {
        printf("encapsulateIP :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }
    memcpy(&tmp[sizeof(struct iphdr)], buffer, *payloadSize);
    struct iphdr *iph = (struct iphdr *) buffer;
    iph -> version = 4;
    iph -> ihl = 5; //minimum number of octets
    iph -> tos = 0;
    iph -> tot_len = htons(*payloadSize + sizeof(struct iphdr)); //len = data + header
    iph -> id = htons(4321);
    iph -> frag_off = 0;
    iph -> ttl = MAXTTL;
    iph -> protocol = IPPROTO_UDP;
    iph -> check = 0;
    iph -> saddr = sourceIP;
    iph -> daddr = destIP;

    iph -> check = checksum(tmp, iph -> ihl * 2); //ip header length is the number of 32-bit words, but csum uses 16 bit words

    *payloadSize += sizeof(struct iphdr);

    return tmp;
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("Invalid Number of arguments...\n");
        printf("Use %s <Source IP to spoof> <Destination IP of listener>\n", argv[0]);
        return -1;
    }

    unsigned char *buff = malloc(sizeof(unsigned char)*13);

    strcpy((char *) buff, "Hello World!");
    int payloadSize = 13;

    buff = encapsulateUDP(buff, &payloadSize, 53);
    buff = encapsulateIP(buff, &payloadSize, inet_addr(argv[1]), inet_addr(argv[2]));

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) {
        perror("Coudn't create socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0);
    inet_pton(AF_INET, argv[2], &server_addr.sin_addr);

    int sent = sendto(sockfd, (char *) buff, payloadSize, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
    
    printf("Sending: %d bytes\n", sent);

    for(int i = 0; i < payloadSize; i++) {
        if(i%4 == 0) printf("\n");
        printf("%02X ", buff[i]);
        
    }
    printf("\n");
    return 0;
}