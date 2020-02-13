CC = gcc

all: dns.o spoof_test spoof_listen dns_listen dns_scan

dns_scan: dns.o dns_scan.c
	$(CC) dns_scan.c -lpthread obj/dns.o -o bin/dns_scan

dns_listen: dns.h dns.o dns_listen.c
	$(CC) dns_listen.c obj/dns.o -o bin/dns_listen

spoof_test: spoof_test.c
	$(CC) spoof_test.c -o bin/spoof_test

spoof_listen: spoof_listen.c
	$(CC) spoof_listen.c -o bin/spoof_listen

dns.o: dns.h dns.c
	$(CC) dns.c -c -o obj/dns.o