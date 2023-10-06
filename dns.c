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

#if 0
bool valid_dns_symbol(char c) 
{
    bool is_letter = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z';
    bool is_digit  = c >= '0' && c <= '9';
    bool is_hyphen = c == '-';
    return is_letter || is_digit || is_hyphen;
}
#endif


#if 0 
    //print answers
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name : %s ",answers[i].name);
 
        if (ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p = (long*)answers[i].rdata;
            a.sin_addr.s_addr = (*p); //working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
         
        if (ntohs(answers[i].resource->type) == T_CNAME) 
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