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

int main() {

    unsigned char *rcv_buff = malloc(65536);
    struct sockaddr_in any;
    socklen_t len = sizeof(any);
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    char *host = malloc(17);
    
    memset(host, 0 , 17);
    if(sockfd < 0) {
        perror("Couldn't create socket");
        return -1;
    }

    while(1) {

        int resp_size = recvfrom(sockfd, rcv_buff, 65536, 0, (struct sockaddr *) &any, &len);

        if(resp_size < 0) {
            perror("Error getting response :/");
            return -1;
        }

        struct iphdr *iph = (struct iphdr*) rcv_buff;

        if(iph -> protocol == 17) {

            unsigned short ipheader_len = iph -> ihl * 4;
            struct udphdr *udph = (struct udphdr *) (rcv_buff + ipheader_len);
            host = inet_ntoa(any.sin_addr);
            printf("Server: %s sent %d byte on port %d\n", host, resp_size, ntohs(udph -> source));
        }
    }
}