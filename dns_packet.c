#include <stdbool.h>

#include "base.h"
#include "dns_packet.h"

uchar buf[BUFFER_SIZE];

static bool answer_name_allocated = false;
static bool answer_rdata_allocated = false;
static dns_answer_t answer;

void dns_answer_free()
{
    if (answer_name_allocated == true) {
        free(answer.name);
        answer_name_allocated = false;
    }
    if (answer_rdata_allocated == true) {
        free(answer.rdata);
        answer_rdata_allocated = false;
    }
}

void dns_host_to_network_format(uchar* dst, uchar* src) 
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

void dns_send_question(int sock_fd, struct sockaddr_in addr, char* domain_name_to_resolve, bool recursion_desired, uint16_t record_type)
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
    int s = sizeof(dns_header_t);
    uchar* qname = (uchar*)&buf[sizeof(dns_header_t)];
 
    dns_host_to_network_format(qname, domain_name_to_resolve);
    dns_qdata_t* qinfo = (dns_qdata_t*)&buf[sizeof(dns_header_t) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons(record_type); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
 
    printf("Resolving %s" , domain_name_to_resolve);

    printf("\nSending Packet... ");
    if (sendto(
        sock_fd, 
        (char*)buf, 
        sizeof(dns_header_t) + (strlen((const char*)qname)+1) + sizeof(dns_qdata_t), 
        0, 
        (struct sockaddr*)&addr,
        sizeof(addr)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done");
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
    default:
        snprintf(tbuf, 15, "%d", type);
        //sprintf(stderr, "Unsupported dns record type %d.", type);
        //return NULL;
        break;
    }
    return tbuf;
}

int dns_print_answer(dns_answer_t ans)
{
    printf("  ");
    printf("%s., ", ans.name);

    const char* type_str = NULL;
    if ((type_str = dns_record_type_to_str(ntohs(ans.resource->type))) == NULL) {
        return 1;
    }

    printf("%s, ", type_str);
    printf("IN, "); // It should always be internet

    printf("%d, ", ntohl(ans.resource->ttl));

    if (ntohs(ans.resource->type) == T_CNAME) {
        printf("%s.\n", ans.rdata);
    } else if (ntohs(ans.resource->type) == T_A) {
        long* p;
        p = (long*)ans.rdata;
        struct sockaddr_in a;
        a.sin_addr.s_addr = (*p); // Works without ntohl
        printf("%s\n", inet_ntoa(a.sin_addr));
    } else if (ntohs(ans.resource->type) == T_AAAA) {
        char* ip6_buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ans.rdata, ip6_buf, INET6_ADDRSTRLEN);
        printf("%s\n", ip6_buf);
    } else {
        printf("\n");
        //sprintf(stderr, "Unsupported record type.\n");
    }
}

int dns_parse_answer(dns_answer_t* ans, uchar* reader, int* ans_real_len)
{
    uchar* reader_ini = reader;

    int stop = 0;
    ans->name = dns_read_name(reader, buf, &stop);
    answer_name_allocated = true;

    reader = reader + stop;

    ans->resource = (dns_ansdata_t*)(reader);
    reader = reader + sizeof(dns_ansdata_t);

    if (ntohs(ans->resource->type) == T_CNAME) {
        stop = 0;
        ans->rdata = dns_read_name(reader, buf, &stop);
        reader = reader + stop;
    } else {
        uint16_t rdata_len = ntohs(ans->resource->data_len);
        if (rdata_len == 0) {
            sprintf(stderr, "RDATA length is zero");
            return 1;
        }

        ans->rdata = malloc(rdata_len);
        answer_rdata_allocated = true;
        memcpy(ans->rdata, reader, rdata_len);

        ans->rdata[rdata_len-1] = '\0';

        reader = reader + rdata_len;
    }

    dns_print_answer(*ans);

    *ans_real_len = reader - reader_ini;
    return 0;
}

int dns_parse_rcode(uint8_t rcode)
{
    switch (rcode) {
        case 0: // Success
            break;
        case 1:
            sprintf(stderr, "Server was unable to interpret the query");
            break;
        case 2:
            sprintf(stderr, "Name server failure");
            break;
        case 3:
            sprintf(stderr, "Authoritative server: domain name does not exist");
            break;
        case 4:
            sprintf(stderr, "Not implemented: name server does not support this kind of query");
            break;
        case 5:
            sprintf(stderr, "Refused for policy reasons");
            break;
        default:
            break;
    }
    return 0;
}

int dns_receive_answers(int sock_fd, struct sockaddr_in addr, char* domain_name_to_resolve)
{
    //Receive the answer
    int addr_len = sizeof(addr);
    printf("\nReceiving answer... ");

    if (recvfrom(sock_fd, (char*)buf, BUFFER_SIZE, 0, (struct sockaddr*)&addr, (socklen_t*)&addr_len) < 0) {
        perror("recvfrom failed");
        return;
    }
    
    printf("Done\n\n");

    //print_packet(buf, BUFFER_SIZE);
 
    dns_header_t* dns = (dns_header_t*)buf;
    dns_parse_rcode(dns->rcode);
    

    printf("Authoritative: %s, ", (dns->aa == 1) ? "Yes" : "No");
    printf("Recursive: %s, ", (dns->rd == 1) ? "Yes" : "No"); // Maybe ra instead of rd?
    printf("Truncated: %s\n", (dns->tc == 1) ? "Yes" : "No"); // What to do with truncated message?
    
    uchar* qname = (uchar*)&buf[sizeof(dns_header_t)];
    dns_host_to_network_format(qname, (uchar*)domain_name_to_resolve);

    dns_qdata_t* qinfo = (dns_qdata_t*)&buf[sizeof(dns_header_t) + (strlen((const char*)qname) + 1)]; //fill it

    printf("Question section (%d)\n", N_QUESTIONS);
    printf("  %s., %s, %s\n", domain_name_to_resolve, ntohs(qinfo->qtype) == T_AAAA ? "AAAA" : "A", "IN");

    //move ahead of the dns header and the query field
    uchar* reader = &buf[sizeof(dns_header_t) + (strlen((const char*)qname)+1) + sizeof(dns_qdata_t)];
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));
    
    printf("Answer section (%d)\n", ntohs(dns->ans_count));

    
    //Start reading answers
    int ans_real_len = 0;    
    for (int i = 0; i < ntohs(dns->ans_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
        dns_answer_free();
    }
 
#if 1
    printf("Authority section (%d)\n", ntohs(dns->auth_count));
    //read authorities
    for (int i = 0; i < ntohs(dns->auth_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
        dns_answer_free();
    }
 
    printf("Additional section (%d)\n", ntohs(dns->add_count));
    //read additional
    for (int i = 0; i < ntohs(dns->add_count); ++i) {
        if (dns_parse_answer(&answer, reader, &ans_real_len) != 0) {
            return 1;
        }
        reader += ans_real_len;
        dns_answer_free();
    }
#else
    printf("Authority section (%d)\n", ntohs(dns->auth_count));
    //read authorities
    for (int i = 0; i < ntohs(dns->auth_count); ++i) {
        auth[i].name = dns_read_name(reader, buf, &stop);
        reader += stop;
 
        auth[i].resource = (dns_ansdata_t*)(reader);
        reader += sizeof(dns_ansdata_t);
 
        auth[i].rdata = dns_read_name(reader, buf, &stop);
        reader += stop;
    }
 
    printf("Additional section (%d)\n", ntohs(dns->add_count));
    //read additional
    for (int i = 0; i < ntohs(dns->add_count); ++i) {
        addit[i].name = dns_read_name(reader, buf, &stop);
        reader += stop;
 
        addit[i].resource = (dns_ansdata_t*)(reader);
        reader += sizeof(dns_ansdata_t);
 
        if (ntohs(addit[i].resource->type) == 1) {
            addit[i].rdata = (uchar*)malloc(ntohs(addit[i].resource->data_len));
            // TODO: replace with memcpy?
            for(int j = 0; j < ntohs(addit[i].resource->data_len); j++) {
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

#endif    
    return 0;
}