#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dns.h"


int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Error: Invalid number of arguments\n");
        printf("Usage: %s <outfile>\n", argv[0]);
        return -1;
    }

    dns_listen_thread(argv[1]);
    
}