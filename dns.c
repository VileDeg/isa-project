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
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define VERBOSE 1



#define MAX_DOMAIN_NAME_LEN 253
#define MIN_PORT 0
#define MAX_PORT 65535
#define PORT_STR_LEN 5
#define DEFAULT_PORT 53
#define MAX_ADDR_LEN 65536

#define MAX_HOST_LEN 1025 // Same as NI_MAXHOST from <netdb.h>

#define R_A 1 // Ipv4 record
#define R_CNAME 5 // Canonical Name record
#define R_AAAA 28 // Ipv6 record
// #define T_NS 2 //Nameserver
// #define T_CNAME 5 // canonical name
// #define T_SOA 6 /* start of authority zone */
// #define T_PTR 12 /* domain name pointer */
// #define T_MX 15 //Mail server

typedef struct {
    bool recursion_desired;
    bool reverse_call;
    bool record_AAAA;
    unsigned char server_name[MAX_DOMAIN_NAME_LEN+1];
    uint16_t port;
    char port_str[PORT_STR_LEN+1];
    char address_str[MAX_ADDR_LEN];
} args_t;


//DNS header structure
// struct DNS_HEADER
// {
//     unsigned short id; // identification number
 
//     unsigned char qr :1; // query/response flag
//     unsigned char opcode :4; // purpose of message
//     unsigned char aa :1; // authoritive answer
//     unsigned char tc :1; // truncated message
//     unsigned char rd :1; // recursion desired
 
//     unsigned char ra :1; // recursion available
//     unsigned char z :3; // its z! reserved
//     unsigned char rcode :4; // response code
//     // unsigned char cd :1; // checking disabled
//     // unsigned char ad :1; // authenticated data
 
//     unsigned short q_count; // number of question entries
//     unsigned short ans_count; // number of answer entries
//     unsigned short auth_count; // number of authority entries
//     unsigned short add_count; // number of resource entries
// };


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
struct addrinfo* gai_ret = NULL;

void terminate(int code) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }
    if (gai_ret != NULL) {
        freeaddrinfo(gai_ret);
    }
    exit(code);
}   

void signal_handler(int signal) {
#if VERBOSE
    printf("\nSignal (%d) received. Terminating...", signal);
#endif
    terminate(0);
}



int parse_args(int argc, char** argv, args_t* outa) 
{
    bool server_set  = false;
    bool address_set = false;

    char flag = '\0';
    for (int i = 1; i < argc; ++i) { // argv[0] is program name
        char* a = argv[i];
        char c = a[0];
        
        
        if (c == '-') {
            flag = a[1];

            switch (flag)
            {
            case 'r': // -r
                outa->recursion_desired = true;
                break;
            case 'x': // -x
                outa->reverse_call = true;
                break;
            case '6': // -6
                outa->record_AAAA = true;
                break;
            case 's':
                break;
            case 'p':
                if (!server_set) { // port name encountered before serv name
                    return 1;
                }
                
                break;
            default:
                return 1;
            }
        } else {
            if (flag == 's') {
                if (!server_set) {
                    memcpy(outa->server_name, a, strlen(a));
                    server_set = true;
                } else {
                    memcpy(outa->address_str, a, strlen(a));
                    address_set = true;
                }
            } else if (flag == 'p') { 
                outa->port = atoi(a);
                if (errno == ERANGE || errno == EINVAL) {
                    fprintf(stderr, "Invalid port value.\n");
                    return 1;
                }
                if (outa->port < MIN_PORT || outa->port > MAX_PORT) {
                    fprintf(stderr, "Port must be in range %d-%d.\n", MIN_PORT, MAX_PORT);
                    return 1;
                }
                memcpy(outa->port_str, a, strlen(a));
            } else {
                return 1;
            }
        }
    }

    if (!server_set || !address_set) { // mandatory options not set
        return 1;
    }

    //TODO validate address
    
    return 0;
}


/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

int main(int argc, char* argv[]) {
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

    
    char* port_str = NULL;
    if (args.port != DEFAULT_PORT) {
        port_str = args.port_str;
    }
    

    struct addrinfo gai_hints; //ipv4, udp
    memset(&gai_hints, 0, sizeof(struct addrinfo));
    gai_hints.ai_socktype = SOCK_DGRAM; // Only request UDP socket address
    gai_hints.ai_flags = AI_NUMERICSERV // Service name is a port number
                       | AI_CANONNAME;  // Request canonical name of the server

    int addr_err = 0;
    if ((addr_err = getaddrinfo(args.server_name, port_str, &gai_hints, &gai_ret)) != 0) {
        fprintf(stderr, "(getaddrinfo) Failed to resolve server address: %s.\n", gai_strerror(addr_err));
    }


    char serv_addr_str[MAX_HOST_LEN];

    struct addrinfo* ai_tmp = NULL;
    for (ai_tmp = gai_ret; ai_tmp != NULL; ai_tmp = ai_tmp->ai_next) {
        if (ai_tmp->ai_family != AF_INET) { // Skip IPv6 for now
            continue;
        }
        //printf("getaddrinfo returned\n");
        //printf("cname: %s\n", ai_tmp->ai_canonname);

        struct sockaddr* addr = ai_tmp->ai_addr;
        //printf("addr: %s\n", addr->sa_data);

        int ni_ret = getnameinfo(addr, ai_tmp->ai_addrlen, serv_addr_str, MAX_HOST_LEN, NULL, 0, NI_NUMERICHOST);
        if (ni_ret) {
            fprintf(stderr, "(getnameinfo) Failed to resolve server address: %s.\n", gai_strerror(ni_ret));
            continue;
        }

        printf("%s: %s\n", (ai_tmp->ai_family == AF_INET ? "IPv4" : "IPv6"), serv_addr_str);
        if (ai_tmp->ai_canonname != NULL) {
            printf("%s\n", ai_tmp->ai_canonname);
        }
        printf("\n");
    }

    unsigned char buf[65536], *qname, *reader;
    int i, j, stop;
 
    struct sockaddr_in a;
 
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
    dest.sin_addr.s_addr = inet_addr(serv_addr_str); // Convert dns server address to binary network format
 
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER*)&buf;
 
    dns->id = (unsigned short)htons(getpid());
    dns->rd = args.recursion_desired; //Recursion Desired
    dns->tc = 0; //This message is not truncated
    dns->aa = 0; //Not Authoritative
    dns->opcode = 0; //This is a standard query
    dns->qr = 0; //This is a query
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    //point to the query portion
    qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    ChangetoDnsNameFormat(qname , host);
    qinfo = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons(args.record_AAAA ? R_AAAA : R_A ); //type of the query , A , MX , CNAME , NS etc
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
    printf("Done");
 
    dns = (struct DNS_HEADER*) buf;
 
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));
    
    //Start reading answers
    stop = 0;
 
    for (i = 0; i < ntohs(dns->ans_count); ++i)
    {
        answers[i].name = ReadName(reader, buf, &stop);
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
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
 
    //read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++) {
        auth[i].name = ReadName(reader, buf, &stop);
        reader += stop;
 
        auth[i].resource = (struct R_DATA*)(reader);
        reader += sizeof(struct R_DATA);
 
        auth[i].rdata = ReadName(reader, buf, &stop);
        reader += stop;
    }
 
    //read additional
    for (i = 0; i < ntohs(dns->add_count); i++) {
        addit[i].name = ReadName(reader, buf, &stop);
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
            addit[i].rdata = ReadName(reader, buf, &stop);
            reader += stop;
        }
    }
 
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

    terminate(retcode);
}
