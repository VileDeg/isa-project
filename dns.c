// Inspired by:
// https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

// Required for 'getaddrinfo'
#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> // Close file descriptor

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "args.h"

#define VERBOSE 1

#define N_QUESTIONS 1 // Send 1 question



#define DEFAULT_PORT 53

//#define MAX_HOST_LEN 1025 // Same as NI_MAXHOST from <netdb.h>

#define R_A 1 // Ipv4 record
#define R_CNAME 5 // Canonical Name record
#define R_AAAA 28 // Ipv6 record
// #define T_NS 2 //Nameserver
// #define T_CNAME 5 // canonical name
// #define T_SOA 6 /* start of authority zone */
// #define T_PTR 12 /* domain name pointer */
// #define T_MX 15 //Mail server



#define USE_HEADER_0 0

#if USE_HEADER_0 == 1
//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char qr :1; // query/response flag
    unsigned char opcode :4; // purpose of message
    unsigned char aa :1; // authoritive answer
    unsigned char tc :1; // truncated message
    unsigned char rd :1; // recursion desired
 
    unsigned char ra :1; // recursion available
    unsigned char z :3; // its z! reserved
    unsigned char rcode :4; // response code
    // unsigned char cd :1; // checking disabled
    // unsigned char ad :1; // authenticated data
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
#else
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
#endif
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

int sock_fd = -1;


void terminate(int code) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }
    
    exit(code);
}   

void signal_handler(int signal) {
#if VERBOSE
    printf("\nSignal (%d) received. Terminating...", signal);
#endif
    terminate(0);
}




void dns_host_to_network_format(unsigned char* dst, unsigned char* src) 
{
    strcat((char*)src, ".");
    ++dst;
    for (unsigned char* dot = dst-1; *src != '\0'; ++src, ++dst) {
        if (*src == '.') {
            *dot = dst - dot - 1;
            dot = dst;
        } else {
            *dst = *src;
        }
    }
    // Remove the added dot to avoid unexpected behavior
    src[strlen((char*)src)-1] = '\0';
}

bool valid_dns_symbol(char c) 
{
    bool is_letter = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z';
    bool is_digit  = c >= '0' && c <= '9';
    bool is_hyphen = c == '-';
    return is_letter || is_digit || is_hyphen;
}

unsigned char* dns_read_name(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0] = '\0';
 
    //read the names in 3www6google3com format
    while (*reader != '\0')
    {
        unsigned char msb = *reader;
        unsigned char lsb = *(reader+1);

        if (msb >= 192) // 192 = 1100 0000
        {
            offset = msb * 256 + lsb - 49152; // 49152 = 1100 0000  0000 0000
            reader = buffer + offset - 1;
            jumped = 1; // We have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }
 
        reader = reader + 1;
 
        if (jumped == 0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p] = '\0'; //string complete
    if (jumped == 1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char*)name); i++) 
    {
        p = name[i];
        for (j = 0; j < (int)p; j++) 
        {
            name[i] = name[i+1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i-1] = '\0'; //remove the last dot
    return name;
}

void resolve_server_address(const char* server_domain_name, const char* server_port, char* server_ip)
{
    struct addrinfo gai_hints; //ipv4, udp
    memset(&gai_hints, 0, sizeof(struct addrinfo));

    gai_hints.ai_flags    = AI_NUMERICSERV | AI_CANONNAME;  // Service name is a port number. Request canonical name of the server
    gai_hints.ai_family   = AF_UNSPEC; 
    gai_hints.ai_socktype = SOCK_DGRAM; // Only request UDP socket address //TODO: remove?
    gai_hints.ai_protocol = IPPROTO_UDP; //TODO: remove?


    printf("Resolving server domain name: %s... ", server_domain_name);

    struct addrinfo* gai_ret = NULL;
    int addr_err = 0;
    if ((addr_err = getaddrinfo(server_domain_name, server_port, &gai_hints, &gai_ret)) != 0) {
        fprintf(stderr, "(getaddrinfo) Failed to resolve server address: %s.\n", gai_strerror(addr_err));
    }
    // if (gai_ret == NULL) {
    //     fprintf(stderr, "(getaddrinfo) Failed to resolve server address: %s.\n", gai_strerror(addr_err));
    // }

    
    
    struct addrinfo* ai_tmp = NULL;
    for (ai_tmp = gai_ret; ai_tmp != NULL; ai_tmp = ai_tmp->ai_next) {
        if (ai_tmp->ai_family != AF_INET) { // Skip IPv6 for now
            continue;
        }

        struct sockaddr_in* h = ai_tmp->ai_addr;
        
#if 1
        strcpy(server_ip, inet_ntoa(h->sin_addr));
#else

        int ni_ret = getnameinfo(ai_tmp->ai_addr, ai_tmp->ai_addrlen, serv_addr_str, MAX_HOST_LEN, NULL, 0, NI_NUMERICHOST);
        if (ni_ret) {
            fprintf(stderr, "(getnameinfo) Failed to resolve server address: %s.\n", gai_strerror(ni_ret));
            continue;
        }
#endif        
        break;
        
        // if (ai_tmp->ai_canonname != NULL) {
        //     printf("%s\n", ai_tmp->ai_canonname);
        // }
    }

    printf("Done\n");
    printf("%s: %s\n\n", (ai_tmp->ai_family == AF_INET ? "IPv4" : "IPv6"), server_ip);
    
    freeaddrinfo(gai_ret);
}


int main(int argc, char* argv[]) 
{
    #ifdef DEBUG
        // Disable buffering
        setbuf(stdout, NULL);
    #endif

    signal(SIGINT , signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    int retcode = 0;

    args_t args;
    memset(&args, 0, sizeof(args_t));
    args.port = DEFAULT_PORT;
    args.port_str[0] = '5';
    args.port_str[1] = '3';

    if ((retcode = parse_args(argc, argv, &args)) != 0) {
        terminate(retcode);
    }

    

    char server_ip[INET6_ADDRSTRLEN+1];
    resolve_server_address(args.server_name, args.port_str, server_ip);

    unsigned char buf[65536], *qname, *reader;
    int i, j, stop;
 
    struct RES_RECORD answers[20], auth[20], addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    char* host = args.address_str;
 
    printf("Resolving %s" , host);

    // AI_NUMERICSERV, gai_strerr

    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sock_fd < 0) {
        perror("Failed creatng socket.");
        terminate(1);
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(args.port);
    dest.sin_addr.s_addr = inet_addr(server_ip); // Convert dns server address to binary network format
 
    // Set the DNS structure to standard queries
    dns = (struct DNS_HEADER*)&buf;
 
    dns->id = (unsigned short)htons(getpid());
    dns->rd = args.recursion_desired; // Recursion Desired
    dns->tc = 0; // This message is not truncated
    dns->aa = 0; // Not Authoritative
    dns->opcode = 0; // This is a standard query
    dns->qr = 0; // This is a query
    dns->ra = 0; // Recursion not available! hey we dont have it (lol)
    dns->z = 0;

#if USE_HEADER_0 == 0
    dns->ad = 0;
    dns->cd = 0;
#endif

    dns->rcode = 0;
    dns->q_count = htons(N_QUESTIONS); // We have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // Point to the query portion
    qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    dns_host_to_network_format(qname, host);
    qinfo = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons(args.record_AAAA ? R_AAAA : R_A); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
 
    printf("\nSending Packet... ");
    if (sendto(
        sock_fd, 
        (char*)buf, 
        sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION), 
        0, 
        (struct sockaddr*)&dest,
        sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done");


    //Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer... ");
    if (recvfrom(sock_fd, (char*)buf, 65536, 0, (struct sockaddr*)&dest, (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Done\n");
 
    dns = (struct DNS_HEADER*) buf;

    printf("Authoritative: %s, ", (dns->aa == 1) ? "Yes" : "No");
    printf("Recursive: %s, ", (dns->rd == 1) ? "Yes" : "No"); // Maybe ra instead of rd?
    printf("Truncated: %s\n", (dns->tc == 1) ? "Yes" : "No"); // What to do with truncated message?

    printf("Question section (%d)\n", N_QUESTIONS);
    printf("  %s., %s, %s\n", host, args.record_AAAA ? "AAAA" : "A", "IN");
    
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    // printf("\nThe response contains : ");
    // printf("\n %d Questions.", ntohs(dns->q_count));
    // printf("\n %d Answers.", ntohs(dns->ans_count));
    // printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    // printf("\n %d Additional records.\n\n", ntohs(dns->add_count));
    
    printf("Answer section (%d)\n", ntohs(dns->ans_count));

    //Start reading answers
    stop = 0;
 
    for (i = 0; i < ntohs(dns->ans_count); ++i)
    {
        answers[i].name = dns_read_name(reader, buf, &stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if (ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            // TODO: replace with memcpy?
            for(j = 0; j < ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j] = reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = dns_read_name(reader, buf, &stop);
            reader = reader + stop;
        }

        printf("  ");
        printf("%s., ", answers[i].name);

        char type[6];
        memset(type, 0, 6);

        switch (ntohs(answers[i].resource->type))
        {
        case R_A:
            memcpy(type, "A", 1);
            break;
        case R_AAAA:
            memcpy(type, "AAAA", 4);
            break;
        case R_CNAME:
            memcpy(type, "CNAME", 5);
            break;
        // TODO: other types?
        default:
            break;
        }

        printf("%s, ", type);
        printf("IN, "); // It should always be internet

        printf("%d, ", ntohl(answers[i].resource->ttl));

        if (ntohs(answers[i].resource->type) != R_CNAME) {
            long* p;
            p = (long*)answers[i].rdata;
            struct sockaddr_in a;
            a.sin_addr.s_addr = (*p); // Works without ntohl
            printf("%s\n", inet_ntoa(a.sin_addr));
        } else {
            printf("%s.\n", answers[i].rdata);
        }

    }
 
    printf("Authority section (%d)\n", ntohs(dns->auth_count));

    //read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++) {
        auth[i].name = dns_read_name(reader, buf, &stop);
        reader += stop;
 
        auth[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);
 
        auth[i].rdata = dns_read_name(reader, buf, &stop);
        reader += stop;
    }
 
    printf("Additional section (%d)\n", ntohs(dns->add_count));

    //read additional
    for (i = 0; i < ntohs(dns->add_count); i++) {
        addit[i].name = dns_read_name(reader, buf, &stop);
        reader += stop;
 
        addit[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);
 
        if (ntohs(addit[i].resource->type) == 1) {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            // TODO: replace with memcpy?
            for(j = 0; j < ntohs(addit[i].resource->data_len); j++) {
                addit[i].rdata[j]=reader[j];
            }
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        }
        else {
            addit[i].rdata = dns_read_name(reader, buf, &stop);
            reader += stop;
        }
    }


#if 0 
    //print answers
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name : %s ",answers[i].name);
 
        if (ntohs(answers[i].resource->type) == R_A) //IPv4 address
        {
            long *p;
            p = (long*)answers[i].rdata;
            a.sin_addr.s_addr = (*p); //working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
         
        if (ntohs(answers[i].resource->type) == R_CNAME) 
        {
            //Canonical name for an alias
            printf("has alias name : %s",answers[i].rdata);
        }
 
        printf("\n");
    }
 
    //print authorities
    printf("\nAuthoritive Records : %d \n", ntohs(dns->auth_count));
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {
        printf("Name : %s ",auth[i].name);
        if (ntohs(auth[i].resource->type)==2)
        {
            printf("has nameserver : %s",auth[i].rdata);
        }
        printf("\n");
    }
 
    //print additional resource records
    printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
    for (i = 0; i < ntohs(dns->add_count); i++)
    {
        printf("Name : %s ",addit[i].name);
        if (ntohs(addit[i].resource->type) == 1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
#endif


    terminate(retcode);
}



/*
<label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]

<ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>

<let-dig-hyp> ::= <let-dig> | "-"

<let-dig> ::= <letter> | <digit>

<letter> ::= any one of the 52 alphabetic characters A through Z in
upper case and a through z in lower case

<digit> ::= any one of the ten digits 0 through 9

<label> ::= <letter> [ [ (((<letter> | <digit>) | "-") | ((<letter> | <digit>) | "-") <ldh-str>) ] (<letter> | <digit>) ]
*/

// Label is a sequence of letters, digits and hyphens but can't end with hyphen

/*
The labels must follow the rules for ARPANET host names.  They must
start with a letter, end with a letter or digit, and have as interior
characters only letters, digits, and hyphen.  There are also some
restrictions on the length.  Labels must be 63 characters or less.
*/

/*
label must be between 3 and 63 characters long
name is 255
*/
