#ifndef __DNS
#define __DNS

/* This code is not portable. C specifies the order of bitwise fields in structs are
* implementation specific. Consider 2 machines, one big endian and one little endian.
* struct numb {
*   unsigned char a : 4;
*   unsigned char b : 4;
*   unsigned char c : 4;
*   unsigned char d : 4;
* };
* Now lets say we assign a = 1, b = 2, c = 3, d = 4.
* On Big-endian:             | On Little-endian: 
*   short: 0x1234            |   short: 0x4321
*   byte array: [0x12, 0x34] |   byte array: [0x21, 0x43]
* Considering our DNS packet (https://tools.ietf.org/html/rfc1035):
*               1  1  1  1  1  1
*      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                      ID                       |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    QDCOUNT                    |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    ANCOUNT                    |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    NSCOUNT                    |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*    |                    ARCOUNT                    |
*    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
* and the struct below, you can see, the feilds for each byte
* are written in reverse order.
*/
struct DNS_HDR {
    unsigned short id; // DNS id
    
    unsigned char rd : 1; //Recursion desired
    unsigned char tc : 1; //Truncation
    unsigned char aa : 1; //Authoritative answer
    unsigned char op : 4; //OPCODE
    unsigned char qr : 1; //query or response

    unsigned char rcode : 4; //RCODE
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z  : 1; //Reserved, must be 0
    unsigned char ra : 1; //Recursion availible

    unsigned short ques_count; //total questions
    unsigned short ans_count; //total answers
    unsigned short auth_count; //total authoritative entries
    unsigned short add_count; //total additional entries
};

struct QUES {
    unsigned short qtype;
    unsigned short qclass;
} ;

#endif
