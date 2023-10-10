#include "base.h"
#include "server.h"

void server_resolve_address(const char* server_domain_name, const char* server_port, char* server_ip)
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
