#include "base.h"
#include "args.h"
#include "dns_packet.h"

int sock_fd = -1;

void terminate(int code) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }

    dns_answer_free();
    
    exit(code);
}   

void signal_handler(int signal) {
#if VERBOSE
    printf("\nSignal (%d) received. Terminating...", signal);
#endif
    terminate(0);
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

    printf("Done\n");
    
#if VERBOSE == 1
    printf("Available addresses:\n");
    char tmpbuf[INET6_ADDRSTRLEN];
#endif
    
    struct addrinfo* ai_tmp = NULL;
    bool ip4_found = false;
    for (ai_tmp = gai_ret; ai_tmp != NULL; ai_tmp = ai_tmp->ai_next) {
        if (ai_tmp->ai_family == AF_INET && !ip4_found) { // Skip IPv6 for now
            ip4_found = true;
            struct sockaddr_in* ip4 = (struct sockaddr_in*)ai_tmp->ai_addr;
            inet_ntop(AF_INET, &ip4->sin_addr, server_ip, INET_ADDRSTRLEN);
        }

#if VERBOSE == 1
        if (ai_tmp->ai_family == AF_INET) {
            struct sockaddr_in* ip4 = (struct sockaddr_in*)ai_tmp->ai_addr;
            inet_ntop(AF_INET, &ip4->sin_addr, tmpbuf, INET_ADDRSTRLEN);
        } else if (ai_tmp->ai_family == AF_INET6) {
            struct sockaddr_in6* ip6 = (struct sockaddr_in6*)ai_tmp->ai_addr;
            inet_ntop(AF_INET6, &ip6->sin6_addr, tmpbuf, INET6_ADDRSTRLEN);
        }
        printf("\t%s\n", tmpbuf);
#endif        
    }

    if (!ip4_found) {
        ai_tmp = gai_ret;
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)ai_tmp->ai_addr;
        inet_ntop(AF_INET6, &ip6->sin6_addr, server_ip, INET6_ADDRSTRLEN);
    }

#if VERBOSE == 1    
    printf("Proceeding with %s address: %s\n\n", (ip4_found ? "IPv4" : "IPv6"), server_ip);
#endif    
    
    freeaddrinfo(gai_ret);
}


int main(int argc, char* argv[]) 
{
    int n = 1;
    // little endian if true
    if(*(char *)&n == 1) {
        printf("Is little endian\n");
    }

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

    char server_ip[INET6_ADDRSTRLEN];
    resolve_server_address((char*)args.server_name, args.port_str, server_ip);

    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sock_fd < 0) {
        perror("Failed creatng socket.");
        terminate(1);
    }

    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(args.port);
    addr.sin_addr.s_addr = inet_addr(server_ip); // Convert dns server address to binary network format

    uint16_t record_type = args.type_ipv6 ? T_AAAA : T_A;

    dns_send_question(sock_fd, addr, args.address_str, args.recursion_desired, record_type);

    dns_receive_answers(sock_fd, addr, args.address_str);

    terminate(retcode);
}

