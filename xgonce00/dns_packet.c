#include <stdbool.h>

#include "base.h"
#include "dns_packet.h"
#include "pkt_print.h"

uchar buf[BUFFER_SIZE];

void dns_name_to_rfc_format(uchar* dst, uchar* src) 
{
    strcat((char*)src, ".");
    ++dst;
    for (uchar* dot = dst-1; *src != '\0'; ++src, ++dst) {
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

uchar* dns_read_name(uchar* reader, uchar* buffer, int* count)
{
    uchar *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;
 
    *count = 1;
    name = (uchar*)malloc(256);
 
    name[0] = '\0';
 
    //read the names in 3www6google3com format
    while (*reader != '\0')
    {
        uchar msb = *reader;
        uchar lsb = *(reader+1);

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

int dns_send_question(int sock_fd, struct sockaddr_in addr, char* domain_name_to_resolve, bool recursion_desired, uint16_t query_type)
{
    dns_header_t *dns = NULL;
    // Set the DNS structure to standard queries
    dns = (dns_header_t*)&buf;
 
    dns->id = (uint16_t)htons(getpid());
    dns->rd = recursion_desired; // Recursion Desired
    dns->tc = 0; // This message is not truncated
    dns->aa = 0; // Not Authoritative
    dns->opcode = 0; // This is a standard query
    dns->qr = 0; // This is a query
    dns->ra = 0; // Recursion not available! hey we dont have it (lol)
    dns->z = 0;

    dns->rcode = 0;
    dns->q_count = htons(N_QUESTIONS); // We have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // Point to the query portion
    uchar* qname = (uchar*)&buf[sizeof(dns_header_t)];
    
    if (query_type != T_PTR) {
        dns_name_to_rfc_format(qname, (uchar*)domain_name_to_resolve);
    } else {
        // Reverse the bytes in IP address
        char* dname = malloc(strlen(domain_name_to_resolve)+1);
        memcpy(dname, domain_name_to_resolve, strlen(domain_name_to_resolve)+1);

        char* octets[4];
        char* octet = strtok(dname, ".");
        for (int i = 0; i < 4; i++) {
            octets[i] = octet;
            octet = strtok(NULL, ".");
        }
        char reversed_octets[16];
        sprintf(reversed_octets, "%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0]);
        char reverse_address[32];
        sprintf(reverse_address, "%s.IN-ADDR.ARPA", reversed_octets); //.
        // Convert the resulting domain name to RFC format
        dns_name_to_rfc_format(qname, (uchar*)reverse_address);
        free(dname);
    }
    dns_qdata_t* qinfo = (dns_qdata_t*)&buf[sizeof(dns_header_t) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons(query_type); // type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); // its internet (lol)
 
    printf("Resolving %s" , domain_name_to_resolve);

    printf("\nSending Packet... ");
    size_t pkt_size = sizeof(dns_header_t) + (strlen((const char*)qname)+1) + sizeof(dns_qdata_t);
    if (sendto(sock_fd, (char*)buf, pkt_size, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("sendto failed");
        return 1;
    }
    printf("Done");

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
    default:
        snprintf(tbuf, 15, "%d", type);
        break;
    }
    return tbuf;
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

    uint16_t rdata_len = ntohs(ans->resource->data_len);
    if (rdata_len == 0) {
        fprintf(stderr, "RDATA length is zero");
        return 1;
    }
    stop = 0;
    switch (type) {
        case T_A:
        case T_AAAA:
            ans->rdata = malloc(rdata_len);
            memcpy(ans->rdata, reader, rdata_len);

            reader += rdata_len;
            
            inet_ntop(type == T_A ? AF_INET : AF_INET6, ans->rdata, ip_buf, len);

            printf("%s\n", ip_buf);
            
            break;
        case T_CNAME:
            ans->rdata = dns_read_name(reader, buf, &stop);

            reader += stop;

            printf("%s.\n", ans->rdata);
            break;
        case T_PTR:
        case T_SOA:
            ans->rdata = dns_read_name(reader, buf, &stop);

            reader += stop;

            printf("%s\n", ans->rdata);
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

int dns_receive_answers(int sock_fd, struct sockaddr_in addr, char* domain_name_to_resolve)
{
    //Receive the answer
    int addr_len = sizeof(addr);
    printf("\nReceiving answer... ");

    if (recvfrom(sock_fd, (char*)buf, BUFFER_SIZE, 0, (struct sockaddr*)&addr, (socklen_t*)&addr_len) < 0) {
        perror("recvfrom failed");
        return 1;
    }
    
    printf("Done\n\n");

#if VERBOSE == 1
    //print_packet(buf, BUFFER_SIZE);
#endif    
 
    dns_header_t* dns = (dns_header_t*)buf;
    if (dns_parse_rcode(dns->rcode) != 0) {
        return 1;
    }

    printf("Authoritative: %s, ", (dns->aa == 1) ? "Yes" : "No");
    printf("Recursive: %s, ", (dns->rd == 1) ? "Yes" : "No"); // Maybe ra instead of rd?
    printf("Truncated: %s\n", (dns->tc == 1) ? "Yes" : "No"); // What to do with truncated message?
    
    uchar* qname = (uchar*)&buf[sizeof(dns_header_t)];
    
    dns_name_to_rfc_format(qname, (uchar*)domain_name_to_resolve);
    //qname = domain_name_to_resolve;

    dns_qdata_t* qinfo = (dns_qdata_t*)&buf[sizeof(dns_header_t) + (strlen((const char*)qname) + 1)]; //fill it

    printf("Question section (%d)\n", N_QUESTIONS);
    printf("  %s., %s, %s\n", domain_name_to_resolve, ntohs(qinfo->qtype) == T_AAAA ? "AAAA" : "A", "IN");

    //move ahead of the dns header and the query field
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
        dns_answer_free();
    }
 
    // Read authorities
    printf("Authority section (%d)\n", ntohs(dns->auth_count));
    for (int i = 0; i < ntohs(dns->auth_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
        dns_answer_free();
    }
 
    // Read additional
    printf("Additional section (%d)\n", ntohs(dns->add_count));
    for (int i = 0; i < ntohs(dns->add_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
        dns_answer_free();
    }

    return 0;
}