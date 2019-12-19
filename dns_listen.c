#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dns.h"


int main(int argc, char *argv[]) {
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

        if(iph -> protocol == IPPROTO_UDP) {

            unsigned short ipheader_len = iph -> ihl * 4;
            struct udphdr *udph = (struct udphdr *) (rcv_buff + ipheader_len);

            if(ntohs(udph->source) == 53) {
                //Get ip address of server that responded
                host = inet_ntoa(any.sin_addr);

                if(strncmp(host, "127", 3) == 0) continue; //ignore local host 
                
                struct DNS_HDR * dns_header = (struct DNS_HDR *) (rcv_buff + ipheader_len + 8);
                if(dns_header -> ra == 1) { 
                    //got a answer 
                    printf("Server: %s Responded with: %d bytes with %hu records\n", host, resp_size, dns_header -> ans_count);
                }
            }
        }
    }
    
}