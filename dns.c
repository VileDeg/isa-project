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

typedef struct {
    bool recursion;
    bool reverse_call;
    bool record_AAAA;
    char server_name[MAX_DOMAIN_NAME_LEN+1];
    int port;
    char port_str[PORT_STR_LEN+1];
    char address[MAX_ADDR_LEN];
} args_t;


//DNS header structure
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

void print_usage(const char* name) {
    // std::cout << std::endl;
    // std::cout << "Usage:\n\n" << name << 
    //     " [-i interface | --interface interface] {-p port} " << 
    //     "{[--tcp|-t] [--udp|-u] [--arp] [--icmp] [--ndp] [--igmp] [--mld]} {-n num}\n" <<
    //     "Options:\n" <<
    //     "\t-i, --interface <interface>  Interface to listen on\n" <<
    //     "\t-p <port>                    Port to listen on\n" <<
    //     "\t-t, --tcp                    Listen on TCP\n" <<
    //     "\t-u, --udp                    Listen on UDP\n" <<
    //     "\t--arp                        Listen on ARP\n" <<
    //     "\t--icmp4                      Listen on ICMPv4\n" <<
    //     "\t--icmp6                      Listen on ICMPv6 (echo request/reply)\n" <<
    //     "\t--ndp                        Listen on NDP\n" <<
    //     "\t--igmp                       Listen on IGMP\n" <<
    //     "\t--mld                        Listen on MLD\n" <<
    //     "\t-n, --num <num>              Number of packets to listen on. Default (1)\n" <<
    //     "\t-h, --help                   Print this help message\n" <<
    //     "Order of arguments does not matter\n\n" <<
    //     name << "[-i|--interface] or " << name << "\n" <<
    //     "\tto print all available interfaces\n\n" <<
    //     "or\n\n" <<
    //     name << "[-help|-h]\n" <<
    //     "\tto print this help message\n\n" <<
    // std::endl;
    return;
}

int parse_args(int argc, char** argv, args_t* outa) {
    const char* const short_opts = "rx6s:p:";
   
    bool server_flag = false;
    int opt = 0;
    while ((opt = getopt(argc, argv, short_opts)) != -1) {
        switch (opt) {
            case 'r': // -r
                outa->recursion = true;
                break;
            case 'x': // -x
                outa->reverse_call = true;
                break;
            case '6': // -6
                outa->record_AAAA = true;
                break;
            case 's': // -s
                memcpy(outa->server_name, optarg, MAX_DOMAIN_NAME_LEN); //TODO
                server_flag = true;
                break;
            case 'p': // -p
                int port = atoi(optarg);
                if (errno == ERANGE || errno == EINVAL) {
                    fprintf(stderr, "Invalid port value.\n");
                    return 1;
                }
                if (port < MIN_PORT || port > MAX_PORT) {
                    fprintf(stderr, "Port must be in range %d-%d.\n", MIN_PORT, MAX_PORT);
                    return 1;
                }
                memcpy(outa->port_str, optarg, PORT_STR_LEN);
                break;
            // case 'h': // -h or --help
            //     print_usage(argv[0]);
            //     return 2;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    if (!server_flag) {
        fprintf(stderr, "Required option for DNS server not specified.\n");
        return 1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    signal(SIGINT , signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    int err = 0;

    args_t args;
    memset(&args, 0, sizeof(args_t));
    args.port = DEFAULT_PORT;

    if ((err = parse_args(argc, argv, &args)) != 0) {
        terminate(err);
    }

    const char* server_name = args.server_name;
    const char* port_str = NULL;
    if (args.port != DEFAULT_PORT) {
        port_str = args.port_str;
    }
    

    struct addrinfo gai_hints; //ipv4, udp
    memset(&gai_hints, 0, sizeof(struct addrinfo));
    gai_hints.ai_socktype = SOCK_DGRAM; // Only request UDP socket address
    gai_hints.ai_flags = AI_NUMERICSERV // Service name is a port number
                       | AI_CANONNAME;  // Request canonical name of the server

    int addr_err = 0;
    if ((addr_err = getaddrinfo(server_name, port_str, &gai_hints, &gai_ret)) != 0) {
        fprintf(stderr, "(getaddrinfo) Failed to resolve server address: %s.\n", gai_strerror(addr_err));
    }


    char addr_str[MAX_HOST_LEN];

    struct addrinfo* ai_tmp = NULL;
    for (ai_tmp = gai_ret; ai_tmp != NULL; ai_tmp = ai_tmp->ai_next) {
        //printf("getaddrinfo returned\n");
        //printf("cname: %s\n", ai_tmp->ai_canonname);

        struct sockaddr* addr = ai_tmp->ai_addr;
        //printf("addr: %s\n", addr->sa_data);

        int ni_ret = getnameinfo(addr, ai_tmp->ai_addrlen, addr_str, MAX_HOST_LEN, NULL, 0, NI_NUMERICHOST);
        if (ni_ret) {
            fprintf(stderr, "(getnameinfo) Failed to resolve server address: %s.\n", gai_strerror(ni_ret));
            continue;
        }

        printf("%s: %s\n", (ai_tmp->ai_family == AF_INET ? "IPv4" : "IPv6"), addr_str);
        if (ai_tmp->ai_canonname != NULL) {
            printf("%s\n", ai_tmp->ai_canonname);
        }
        printf("\n");
    }

    // AI_NUMERICSERV, gai_strerr

    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sock_fd < 0) {
        perror("Failed creatng socket.");
        terminate(1);
    }

    terminate(err);
}
