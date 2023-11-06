/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#include "base.h"
#include "dns_packet.h"

uchar buf[BUFFER_SIZE];


int dns_domain_to_ip(const char* server_domain_name, serv_addr_t* serv)
{
    struct addrinfo gai_hints; //ipv4, udp
    memset(&gai_hints, 0, sizeof(struct addrinfo));

    // Service name is a port number. Request canonical name of the server
    gai_hints.ai_flags    = AI_NUMERICSERV | AI_CANONNAME;
    gai_hints.ai_family   = AF_UNSPEC; // IPv4 or IPv6
    gai_hints.ai_socktype = SOCK_DGRAM; // UDP
    gai_hints.ai_protocol = IPPROTO_UDP;

#if VERBOSE == 1
    printf("Resolving server domain name: %s... ", server_domain_name);
#endif

    struct addrinfo* gai_ret = NULL;
    int addr_err = 0;
    if ((addr_err = getaddrinfo(server_domain_name, "53", &gai_hints, &gai_ret)) != 0 || gai_ret == NULL) {
        fprintf(stderr, "(getaddrinfo) Failed to resolve server address: %s.\n", gai_strerror(addr_err));
        return 1;
    }

#if VERBOSE == 1
    printf("Done\n");
#endif    
    
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
            serv->addr_ip4.sin_family = AF_INET;
            serv->addr_ip4.sin_addr = ip4->sin_addr;
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

    //*ip_type4 = ip4_found;
    serv->ipv4 = ip4_found;

    // If no IPv4 address was found, use IPv6
    if (!ip4_found) {
        ai_tmp = gai_ret;
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)ai_tmp->ai_addr;
        serv->addr_ip6.sin6_family = AF_INET6;
        serv->addr_ip6.sin6_addr = ip6->sin6_addr;
    }

#if VERBOSE == 1    
    printf("Proceeding with %s address: %s\n\n", (ip4_found ? "IPv4" : "IPv6"), server_ip);
#endif    
    
    freeaddrinfo(gai_ret);
    return 0;
}




const char* dns_record_type_to_str(uint16_t type)
{
    static char tbuf[16];
    memset(tbuf, 0, 16);

    switch (type)
    {
    case T_A:
        memcpy(tbuf, "A", 1);
        break;
    case T_AAAA:
        memcpy(tbuf, "AAAA", 4);
        break;
    case T_CNAME:
        memcpy(tbuf, "CNAME", 5);
        break;
    case T_SOA:
        memcpy(tbuf, "SOA", 3);
        break;
    case T_PTR:
        memcpy(tbuf, "PTR", 3);
        break;
    case T_NS:
        memcpy(tbuf, "NS", 2);
        break;
    default:
        snprintf(tbuf, 15, "%d", type);
        break;
    }
    return tbuf;
}

int dns_parse_rcode(uint8_t rcode)
{
    switch (rcode) {
        case 0: // Success
            break;
        case 1:
            fprintf(stderr, "Error: Server was unable to interpret the query.\n");
            break;
        case 2:
            fprintf(stderr, "Error: Name server failure.\n");
            break;
        case 3:
            fprintf(stderr, "Error: Authoritative server: domain name does not exist.\n");
            break;
        case 4:
            fprintf(stderr, "Error: Not implemented: name server does not support this kind of query.\n");
            break;
        case 5:
            fprintf(stderr, "Error: Refused for policy reasons.\n");
            break;
        default:
            break;
    }
    return rcode != 0;
}


// E.g. convert www.google.com to 3www6google3com0
void dns_encode_name(uchar* dst, uchar* src) 
{
    strcat((char*)src, ".");

    int di = 0;
    for (int i = 0; i < strlen((char*)src); ++i) {
        if (src[i] == '.') {
            dst[di] = i - di;
            di = i+1;
        } else {
            dst[i+1] = src[i];
        }
    }

    src[strlen((char*)src)-1] = '\0';
}


int dns_reverse_ipv4(char* out_addr, const char* in_addr) {
    // Check if the address is an IP address
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, in_addr, &ipv4_addr) == 1) {
        // Reverse the byte order of the IP address
        uint32_t addr_value = ntohl(ipv4_addr.s_addr);
        memcpy(&ipv4_addr.s_addr, &addr_value, sizeof(addr_value));
        inet_ntop(AF_INET, &ipv4_addr, out_addr, INET_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Invalid IPv4 address %s.\n", in_addr);
        return 1;
    }

    strcat(out_addr, ".in-addr.arpa");
    return 0;
}

int dns_reverse_ipv6(char* out_addr, const char* in_addr) {
    struct in6_addr ipv6;

    char expanded[INET6_ADDRSTRLEN];

    if (inet_pton(AF_INET6, in_addr, &ipv6) == 1) {
        // Expand the IPv6 address
        for (int i = 0; i < 8; i++) {
            sprintf(expanded + i * 5, "%04x", ntohs(((uint16_t*)&ipv6)[i]));
            if (i < 7) {
                expanded[i * 5 + 4] = ':';
            }
        }
    } else {
        fprintf(stderr, "Invalid IPv6 address: %s\n", in_addr);
        return 0;
    }

    int j = 0;
    for (int i = strlen(expanded)-1; i >= 0; --i) {
        if (expanded[i] == ':') {
            continue;
        }
        out_addr[j] = expanded[i];
        if (i > 0) {
            out_addr[j+1] = '.';
        }
        j += 2;
    }

    strcat(out_addr, ".ip6.arpa");
    return 0;
}



uchar* dns_read_name(uchar* reader, uchar* buffer, int* count)
{
    unsigned int p = 0, jumped = 0, offset;
    
    uchar *name = (uchar*)malloc(256);
    name[0] = '\0';
 
    *count = 1;
 
    // Read the names in e.g. 3www6github3com format
    while (*reader != '\0') {
        uchar msb = *reader;
        uchar lsb = *(reader+1);

        // If msb is 11XX XXXX then we have a pointer to another location
        if (msb >= 192) { // 192 = 1100 0000 
            offset = msb * 256 + lsb - 49152; // 49152 = 1100 0000  0000 0000
            reader = buffer + offset - 1;
            jumped = 1; // We have jumped to another location so counting wont go up!
        } else {
            name[p] = *reader;
            ++p;
        }
 
        reader = reader + 1;
 
        if (jumped == 0) {
            *count += 1; // If we havent jumped to another location then we can count up
        }
    }
 
    name[p] = '\0'; // String complete
    if (jumped == 1) {
        *count += 1; // Number of steps we actually moved forward in the packet
    }
 
    // Now convert e.g. 3www6github3com to www.github.com
    int i = 0;
    for (i = 0; i < (int)strlen((const char*)name); i++) {
        p = name[i];
        for (int j = 0; j < (int)p; j++) {
            name[i] = name[i+1];
            i = i + 1;
        }
        name[i] = '.';
    }

    if (i > 0) {
        name[i-1] = '\0'; // Remove the last dot
    }

    return name;
}


int dns_send_question(int sock_fd, serv_addr_t serv, char* domain_or_ip, bool recursion_desired, uint16_t query_type)
{
    // Fill in the DNS header
    dns_header_t *dns = (dns_header_t*)&buf;
    
    dns->id = (uint16_t)htons(getpid());
    dns->rd = recursion_desired;
    dns->tc = 0; // This message is not truncated
    dns->aa = 0; // Not Authoritative
    dns->opcode = 0; // This is a standard query
    dns->qr = 0; // This is a query
    dns->ra = 0; // Recursion not available
    dns->z = 0;

    dns->rcode = 0;
    dns->q_count = htons(N_QUESTIONS); // We have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // Point to the query portion
    uchar* qname = (uchar*)&buf[sizeof(dns_header_t)];

    char out_address[INET6_ADDRSTRLEN*2+9];
    memset(out_address, 0, INET6_ADDRSTRLEN*2+9);
    
    if (query_type != T_PTR) { // Forward query
        memcpy(out_address, domain_or_ip, strlen(domain_or_ip));
    } else { // Reverse query
        struct in_addr ipv4;
        struct in6_addr ipv6;

        // Attempt to parse the address as IPv4
        if (inet_pton(AF_INET, domain_or_ip, &ipv4) == 1) {
            // Reverse the bytes in IP address and append .IN-ADDR.ARPA
            if (dns_reverse_ipv4(out_address, domain_or_ip) != 0) {
                return 1;
            }
        // Attempt to parse the address as IPv6 
        } else if (inet_pton(AF_INET6, domain_or_ip, &ipv6) == 1) {
            // Reverse the IPv6 address and append .IP6.ARPA
            if (dns_reverse_ipv6(out_address, domain_or_ip) != 0) {
                return 1;
            }
        } else {
            fprintf(stderr, "Not a valid IPv4 or IPv6 address: %s\n", domain_or_ip);
            return 1;
        }
    }

    // Encode the resulting domain name
    dns_encode_name(qname, (uchar*)out_address);

    // Point to the qinfo section
    dns_qdata_t* qinfo = (dns_qdata_t*)&buf[sizeof(dns_header_t) + (strlen((const char*)qname) + 1)];
 
    qinfo->qtype  = htons(query_type);
    qinfo->qclass = htons(1);

#if VERBOSE == 1 
    printf("Resolving %s" , domain_or_ip);

    printf("\nSending Packet... ");
#endif    

    // Send the packet to the server
    size_t pkt_size = sizeof(dns_header_t) + (strlen((const char*)qname)+1) + sizeof(dns_qdata_t);

    struct sockaddr* server_addr = serv.ipv4 ? 
        (struct sockaddr*)&(serv.addr_ip4) : (struct sockaddr*)&(serv.addr_ip6);
    
    socklen_t server_addr_len = serv.ipv4 ? 
        sizeof(serv.addr_ip4) : sizeof(serv.addr_ip6);

    if (sendto(sock_fd, (char*)buf, pkt_size, 0, server_addr, server_addr_len) < 0) {
        perror("sendto failed");
        return 1;
    }
#if VERBOSE == 1     
    printf("Done\n");
#endif    

    printf("Question section (%d)\n", N_QUESTIONS);
    printf("  %s., %s, %s\n", out_address, dns_record_type_to_str(ntohs(qinfo->qtype)), "IN");

    return 0;
}

int dns_parse_answer(dns_answer_t* ans, uchar* reader, int* ans_real_len)
{
    uchar* reader_ini = reader;

    int stop = 0;
    ans->name = dns_read_name(reader, buf, &stop);

    reader += stop;

    ans->resource = (dns_ansdata_t*)(reader);
    reader += sizeof(dns_ansdata_t);


    printf("  ");
    printf("%s., ", ans->name);
    free(ans->name);
    ans->name = NULL;

    const char* type_str = dns_record_type_to_str(ntohs(ans->resource->type));

    printf("%s, ", type_str);
    printf("IN, "); // It should always be internet

    printf("%d, ", ntohl(ans->resource->ttl));

    uint16_t type = ntohs(ans->resource->type);
    size_t len = type == T_A ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char ip_buf[len];


    // Parse RDATA
    uint16_t rdata_len = ntohs(ans->resource->data_len);
    if (rdata_len == 0) {
        fprintf(stderr, "RDATA is empty.\n");
        return 1;
    }

    stop = 0;
    switch (type) {
        case T_A:
        case T_AAAA:
            ans->rdata = malloc(rdata_len);
            memcpy(ans->rdata, reader, rdata_len);

            reader += rdata_len;
            
            if (inet_ntop(type == T_A ? AF_INET : AF_INET6, ans->rdata, ip_buf, len) == NULL) {
                free(ans->rdata);
                perror("inet_ntop: invalid address in RDATA (A/AAAA)");
                return 1;
            }

            printf("%s\n", ip_buf);
            break;
        case T_NS: case T_MX: case T_SOA:
        case T_CNAME: case T_PTR:
            ans->rdata = dns_read_name(reader, buf, &stop);

            reader += stop;

            printf("%s.\n", ans->rdata);  
            break;            
        default:
            printf("\n");
            break;
    }

    free(ans->rdata);
    ans->rdata = NULL;

    *ans_real_len = reader - reader_ini;
    return 0;
}


int dns_receive_answers(int sock_fd, serv_addr_t serv)
{
#if VERBOSE == 1  
    printf("\nReceiving answer... ");
#endif

    struct sockaddr* server_addr = serv.ipv4 ? 
        (struct sockaddr*)&(serv.addr_ip4) : (struct sockaddr*)&(serv.addr_ip6);

    socklen_t server_addr_len = serv.ipv4 ? sizeof(serv.addr_ip4) : sizeof(serv.addr_ip6);

    if (recvfrom(sock_fd, (char*)buf, BUFFER_SIZE, 0, server_addr, &server_addr_len) < 0) {
        perror("recvfrom failed");
        return 1;
    }

#if VERBOSE == 1      
    printf("Done\n\n");
#endif    

    dns_header_t* dns = (dns_header_t*)buf;
    if (dns_parse_rcode(dns->rcode) != 0) {
        return 1;
    }

    printf("Authoritative: %s, ", (dns->aa == 1) ? "Yes" : "No");
    printf("Recursive: %s, ", (dns->rd == 1) ? "Yes" : "No"); // Maybe ra instead of rd?
    printf("Truncated: %s\n", (dns->tc == 1) ? "Yes" : "No"); // What to do with truncated message?
    
    uchar* qname = (uchar*)&buf[sizeof(dns_header_t)];
 
    uchar* reader = &buf[sizeof(dns_header_t) + (strlen((const char*)qname)+1) + sizeof(dns_qdata_t)];

#if VERBOSE == 1 
    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));
#endif

    dns_answer_t answer;
    memset(&answer, 0, sizeof(dns_answer_t));

    // Read answers
    printf("Answer section (%d)\n", ntohs(dns->ans_count));
    int ans_real_len = 0;    
    for (int i = 0; i < ntohs(dns->ans_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
    }
 
    // Read authorities
    printf("Authority section (%d)\n", ntohs(dns->auth_count));
    for (int i = 0; i < ntohs(dns->auth_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
    }
 
    // Read additional
    printf("Additional section (%d)\n", ntohs(dns->add_count));
    for (int i = 0; i < ntohs(dns->add_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
    }

    return 0;
}

