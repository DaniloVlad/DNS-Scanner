#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <time.h>
#include "dns.h"

void formatDNSName(unsigned char* dns,unsigned char* host)
{
    if(strncmp((const char *) host, ".", 1) == 0) 
        *dns++ = '\0';
    
        
    else {
        char *token = strtok((char *) host, ".");
        do {

            *dns++ = strlen((char *) token);
            for(int i = 0; i < strlen((const char *) token) ; i++)  
                *dns++ = token[i];

        } while((token = strtok(NULL, ".")) != NULL);
    }
    
    *dns++ = '\0';

        
}

unsigned char *addEDNS(unsigned char *buffer, int *payloadSize) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + 11);

    if(!tmp) {
        perror("addEDNS :: Couldn't reallocate buffer");
    }

    void *edns = (void *) &tmp[*payloadSize + 1];
    memset(edns, 0x00, 1);
    memset(edns + 1, 0x29, 1); //set edns RR type code '41'
    memset(edns + 2, 0xFF, 2); //set edns send UDP Max size
    memset(edns + 4, 0x00, 7); //set remaining fields to 0

    *payloadSize += 11;

    return tmp;
}

unsigned char *addQuestion(unsigned char *buffer, int *payloadSize) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + sizeof(struct QUES));

    if(!tmp) {
        perror("addQuestion :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    struct QUES *question = (struct QUES *)&tmp[*payloadSize];
    question -> qtype = htons(255);
    question -> qclass = htons(1);

    *payloadSize += sizeof(struct QUES);
    return tmp;
}

unsigned char *addRecord(unsigned char *buffer, unsigned char *query_name, int *payloadSize) {

    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + strlen((const char *) query_name) + 1);

    if(!tmp) {
        perror("addRecord :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    unsigned char *qname = &tmp[*payloadSize];
    formatDNSName(qname, query_name);
    *payloadSize += strlen( (const char *) qname) + 1;

    return tmp;
}

unsigned char *encapsulateDNS(unsigned char *buffer, int *payloadSize) {

    unsigned char *tmp = NULL;
    tmp = realloc(buffer, (*payloadSize) + sizeof(struct DNS_HDR));

    if(!tmp) {
        perror("encapsulateDNS :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(&tmp[sizeof(struct DNS_HDR)], buffer, *payloadSize);

    struct DNS_HDR *dnsh = (struct DNS_HDR *) tmp;
    dnsh -> id = (unsigned short) htons(rand());
    dnsh -> qr = 0; //this is a query
    dnsh -> op = 0;
    dnsh -> aa = 0;
    dnsh -> tc = 0;
    dnsh -> rd = 1; //want resolver to do the resolution

    dnsh -> ra = 0;
    dnsh -> z = 0;
    dnsh -> ad = 0;
    dnsh -> cd = 0;
    dnsh -> rcode = 0;

    dnsh -> ques_count = htons(1);
    dnsh -> ans_count = 0;
    dnsh -> auth_count = 0;
    dnsh -> add_count = htons(1);

    *payloadSize += sizeof(struct DNS_HDR);

    return tmp;
}

void *dns_listen_thread(void *args) {
    char * file_name = args;
    FILE *outfile = fopen(file_name, "w");
    
    if(outfile == NULL) {
        printf("Error opening outfile!\n");
        exit(-1);
    }
    else {
        printf("Starting listener to file: %s...\n", file_name);
    }

    unsigned char *rcv_buff = malloc(65536);
    struct sockaddr_in any;
    socklen_t len = sizeof(any);
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    char *host = malloc(17);
    
    memset(host, 0 , 17);

    if(sockfd < 0) {
        perror("Couldn't create socket");
        exit(-1);
    }

    while(1) {

        int resp_size = recvfrom(sockfd, rcv_buff, 65536, 0, (struct sockaddr *) &any, &len);

        if(resp_size < 0) {
            perror("Error getting response :/");
            exit(-1);
        }

        struct iphdr *iph = (struct iphdr*) rcv_buff;
        if(iph -> protocol == 17) {
            unsigned short ipheader_len = iph -> ihl * 4;
            struct udphdr *udph = (struct udphdr *) (rcv_buff + ipheader_len);

            if(ntohs(udph->source) == 53) {
                //Get ip address of server that responded
                host = inet_ntoa(any.sin_addr);

                if(strncmp(host, "127", 3) == 0 || strncmp(host, "192", 3) == 0 || strncmp(host, "10.", 3) == 0) continue; //ignore local host  ? ip addr = FF.FF.FF.FF, so if any.sin_addr < 0xFF000000 ?
                
                struct DNS_HDR * dns_header = (struct DNS_HDR *) (rcv_buff + ipheader_len + 8);
                if(dns_header -> ra == 1) { 
                    //got a answer 
                    fprintf(outfile,"%s %d\n", host, resp_size);
                    fflush(outfile);
                }
            }
        }
    }
}