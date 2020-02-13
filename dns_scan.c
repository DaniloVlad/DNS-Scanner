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

typedef struct range {
    unsigned long start;
    unsigned long amount;
    in_addr_t spoof_ip;
    unsigned char *host;
} Thread_Data;

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

void *scan_thread(void *args) {

    //TO-DO: Remove scanning special purpose IP ranges (private IPs)
    //as per https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    
    Thread_Data *td = (Thread_Data *) args;

    unsigned char *buff = NULL;
    int payloadSize = 0;

    int socket_type = SOCK_DGRAM;
    int socket_protocol = IPPROTO_UDP;

    //add the record 
    buff = addRecord(buff, td -> host, &payloadSize);
    //add the record details
    buff = addQuestion(buff, &payloadSize);
    //add extended DNS
    buff = addEDNS(buff, &payloadSize);
    //add DNS header around data
    buff = encapsulateDNS(buff, &payloadSize);

    if(td->spoof_ip) {
        socket_type = SOCK_RAW;
        socket_protocol = IPPROTO_RAW;
        //add UDP header
        buff = encapsulateUDP(buff, &payloadSize, 53); //port 53 default dns
        buff = encapsulateIP(buff, &payloadSize, td -> spoof_ip, 0);
    }

    int sockfd = socket(AF_INET, socket_type, socket_protocol);
    if(sockfd < 0) {
        perror("Coudn't create socket");
        exit(-1);
    }

    struct sockaddr_in server_addr;
    for(uint32_t ip = td -> start; ip < td -> start + td -> amount + 1; ip++) {

        memset(&server_addr, 0, sizeof(server_addr));

        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(ip);

        if(td -> spoof_ip) {
            //add IP header with spoofed source IP
            struct iphdr *iph = (struct iphdr *)buff;
            iph -> daddr = htonl(ip);
            iph -> check = checksum(iph, iph -> ihl *2);
            server_addr.sin_port = 0;
        }
        else
            server_addr.sin_port = htons(53);
        
        int sent = sendto(sockfd, (char *) buff, payloadSize, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
        
    }

}

int start_scanning(int numThreads, in_addr_t start_ip, in_addr_t end_ip, unsigned char *spoof_ip, unsigned char *host) {
    unsigned long ips_per_thread = (ntohl(end_ip) - ntohl(start_ip))/numThreads;
    pthread_t threads[numThreads];
    printf("IPs per thread: %ld\n", ips_per_thread);

    for(int i = 0; i < numThreads; i++) {
        Thread_Data *new_td = (Thread_Data *) malloc(sizeof(Thread_Data));
        new_td -> host = malloc(strlen(host) + 1);
        strcpy(new_td -> host, host);
        new_td -> start = (ntohl(start_ip) + i*ips_per_thread);
        new_td -> amount = ips_per_thread;
        if(spoof_ip)
            new_td -> spoof_ip = inet_addr(spoof_ip);
        else
            new_td -> spoof_ip = 0;

        pthread_create(&threads[i], NULL, &scan_thread, new_td);
    }

    for(int j = 0; j < numThreads; j++) pthread_join(threads[j], NULL);
}


int main(int argc, char *argv[]) {

    if(argc < 2) {
        printf("Error: Invalid argument length\n");
        printf("Options:\n\t-h DNS Server IP (single scan)\n\t-d Domain to resolve\n\t-S IP of server with DNS Listener (spoof scan)\n\t-s Start IP (DNS scan range)\n\t-e End IP (DNS scan range)\n\t-t Thread count (optional default = 1)\n\t-l Listener output file (Optional default = 'dns_outfile')(Not for spoof scanning)\n");
        printf("Usage:\n\t%s -h <DNS Server> - Test single server\n\t%s -h <DNS Server> -d <Domain> - Test single domain on single server\n\t%s -h <DNS Server> -d <Domain> -S <Server IP> - Test Single Domain on spoofed listener\n\t%s -s <Start IP> -e <End IP> (-S <Server IP>) - Scan range of IP's (Can also be spoofed)\n", argv[0], argv[0], argv[0], argv[0]);
        return -1;
    }

    
    int opt;
    int payloadSize = 0;
    int thread_count = 1;

    int socket_type = SOCK_DGRAM;
    int socket_protocol = IPPROTO_UDP;

    char *dns_server = NULL, *listen_file = "dns_outfile";
    unsigned char *host = NULL, 
    *req_ip = NULL, 
    *start_ip = NULL, 
    *end_ip = NULL,
    *buff = NULL;

    while((opt = getopt(argc, argv,"h:S:s:e:d:t:l:")) > 0) {

        switch (opt)
        {
        case 'h': //specifies dns server

            printf("Host was specified: %s\n", optarg);
            dns_server = (char *) malloc(strlen(optarg) + 1);
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
            break;
        case 'l':
            listen_file = malloc(strlen(optarg) + 1);
            strcpy(listen_file, optarg);
        default:
            break;
        }
    }

    srand(time(NULL));

    if(host == NULL) {
        printf("Using default domain\n");
        host = (unsigned char *) malloc(50);
        strcpy((char *) host, "..");
    }    

    if(host == NULL) {
        perror("Couldn't allocate host");
        return -1; 
    }

    if(req_ip == NULL) { //spoofing scanning was not selected
        pthread_t listen_id;
        pthread_create(&listen_id, NULL, &dns_listen_thread, (void *) listen_file);
        sleep(2); //wait for thread to init
    }
    
    if(start_ip && end_ip) {
        in_addr_t start, end;
        inet_pton(AF_INET, start_ip, &start);
        inet_pton(AF_INET, end_ip, &end); //for ip 255.255.255.255 this returns -1
        start_scanning(thread_count, start, end, req_ip, host);
    }
    else {
        if(!dns_server) {
            perror("Invalid DNS server!");
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

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(53);
        inet_pton(AF_INET, dns_server, &server_addr.sin_addr);

        if(req_ip) {
            socket_type = SOCK_RAW;
            socket_protocol = IPPROTO_RAW;

            //add UDP header
            buff = encapsulateUDP(buff, &payloadSize, 53); //port 53 default dns
            //add IP header with spoofed source IP
            buff = encapsulateIP(buff, &payloadSize, inet_addr((const char *) req_ip), inet_addr((const char *) dns_server));
            server_addr.sin_port = htons(0);
        }

        int sockfd = socket(AF_INET, socket_type, socket_protocol);
        if(sockfd < 0) {
            perror("Coudn't create socket");
            return -1;
        }          

        int sent = sendto(sockfd, (char *) buff, payloadSize, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
        printf("Sending: %d bytes\n", sent);

        if(sent < 0) {
            printf("Error sending packet!\n");
            return -1;
        }
        for(int i = 0; i < payloadSize; i++) {
            if(i%8 == 0) printf("\n");
            printf("%02X ", buff[i]);
            
        }
        printf("\n");   
        close(sockfd);
    }
    sleep(2); //let the last couple of responses roll in
    

    if(host) free(host); 
    if(dns_server) free(dns_server);
    if(req_ip) free(req_ip);
    if(buff) free(buff);
    if(start_ip) free(start_ip);
    if(end_ip) free(end_ip);

    return 0;
}