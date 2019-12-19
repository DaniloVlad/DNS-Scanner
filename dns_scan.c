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
#include "dns.h"


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

// 3.1. Name space definitions
// Domain names in messages are expressed in terms of a sequence of labels.
// Each label is represented as a one octet length field followed by that
// number of octets. 
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

void test_csum() {
    unsigned short tbuf[10] = {0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0x0000 ,0xc0a8, 0x0001, 0xc0a8, 0x00c7};

    printf("Test checksum: %04X\n", checksum(tbuf, 10));

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

    *payloadSize += 12;

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

    *payloadSize += sizeof(struct udphdr);

    return tmp;
}

unsigned char *encapsulateIP(unsigned char *buffer, int *payloadSize, in_addr_t sourceIP, in_addr_t destIP) {
    unsigned char *tmp = NULL;
    tmp = realloc(buffer, *payloadSize + sizeof(struct iphdr));

    if(!tmp) {
        perror("encapsulateUDP :: Couldn't reallocate buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(&tmp[sizeof(struct iphdr)], buffer, *payloadSize);

    struct iphdr *iph = (struct iphdr *) buffer;
    iph -> version = 4;
    iph -> ihl = 5; //minimum number of octets
    iph -> tos = 0;
    iph -> tot_len = htons(*payloadSize + sizeof(struct iphdr)); //len = data + header
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

    if(argc < 2) {
        printf("Error: Invalid argument length\n");
        printf("Options:\n\t-h DNS Server IP (single scan)\n\t-d Domain to resolve\n\t-S IP of server with DNS Listener (spoof scan)\n\t-s Start IP (DNS scan range)\n\t-e End IP (DNS scan range)\n\t-t Thread count (optional default = 0)\n");
        printf("Usage:\n\t%s -h <DNS Server> - Test single server\n\t%s -h <DNS Server> -d <Domain> - Test single domain on single server\n\t%s -h <DNS Server> -d <Domain> -S <Server IP> - Test Single Domain on spoofed listener\n\t%s -s <Start IP> -e <End IP> (-S <Server IP>) - Scan range of IP's (Can also be spoofed)\n", argv[0], argv[0], argv[0], argv[0]);
        return -1;
    }

    
    int opt;
    int payloadSize = 0;
    int thread_count = 0;

    unsigned char *host = NULL, 
    *req_ip = NULL, 
    *dns_server = NULL, 
    *start_ip = NULL, 
    *end_ip = NULL,
    *buff = NULL;

    while((opt = getopt(argc, argv,"h:S:s:e:d:t:")) > 0) {

        switch (opt)
        {
        case 'h': //specifies dns server

            printf("Host was specified: %s\n", optarg);
            dns_server = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) dns_server, optarg);
            break;
        
        case 'S':
            printf("Spoofing enabled. Responses will go to: %s\n", optarg);
            req_ip = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) req_ip, optarg);
            break;
        
        case 's':
            printf("Start IP: %s\n", optarg);
            start_ip = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) start_ip, optarg);
            break;
        case 'e':
            printf("End IP: %s\n", optarg);
            end_ip = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) end_ip, optarg);
            break;
        case 'd':
            printf("Domain name: %s\n", optarg);
            host = (unsigned char *) malloc(strlen(optarg) + 1);
            strcpy((char *) host, optarg);
            break;
        case 't':
            printf("Using %d Threads\n", atoi(optarg));
            thread_count = atoi(optarg);
        default:
            break;
        }
    }

    srand(time(NULL));

    if(host == NULL) {
        printf("Using default host\n");
        host = (unsigned char *) malloc(50);
        strcpy((char *) host, "..");
    }    

    if(host == NULL) {
        perror("Couldn't allocate host");
        return -1; 
    }

    //add the record 
    buff = addRecord(buff, host, &payloadSize);
    //add the record details
    buff = addQuestion(buff, &payloadSize);
    //add extended DNS
    buff = addEDNS(buff, &payloadSize);
    //add DNS header around data
    buff = encapsulateDNS(buff, &payloadSize);

    
    if(req_ip) {
        //add UDP header
        buff = encapsulateUDP(buff, &payloadSize, 53); //port 53 default dns
        //add IP header with spoofed source IP
        buff = encapsulateIP(buff, &payloadSize, inet_addr((const char *) req_ip), inet_addr((const char *) dns_server));
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("Coudn't create socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    server_addr.sin_addr.s_addr = inet_addr((const char *) dns_server);

    int sent = sendto(sockfd, (char *) buff, payloadSize, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
    printf("Sending: %d bytes\n", sent);

    
    for(int i = 0; i < payloadSize; i++) {
        if(i%8 == 0) printf("\n");
        printf("%02X ", buff[i]);
        
    }
    printf("\n");   

    free(host); 
    return 0;
}