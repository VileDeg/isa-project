/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#ifndef __DNS_PACKET_H__
#define __DNS_PACKET_H__

// The following data structures are defined by RFC 1035.
// But this definition is also inspired by the following gist:
// https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168 (no license specified)
typedef struct {
    uint16_t id;
 
    uint8_t  rd :1; // Recursion desired
    uint8_t  tc :1; // Truncated message
    uint8_t  aa :1; // Authoritive answer
    uint8_t  opcode :4; // Purpose of message
    uint8_t  qr :1; // Query/response flag

    uint8_t  rcode :4; // Response code
    uint8_t  cd :1; // Checking disabled
    uint8_t  ad :1; // Authenticated data
    uint8_t  z :1; // Zero (reserved)
    uint8_t  ra :1; // Recursion available
 
    uint16_t q_count; // Number of question entries
    uint16_t ans_count; // Number of answer entries
    uint16_t auth_count; // Number of authority entries
    uint16_t add_count; // Number of resource entries
} dns_header_t;
 
// Constant sized fields of query structure
typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_qdata_t;
 
// Constant sized fields of the resource record structure
#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
} dns_ansdata_t;
#pragma pack(pop)
 
// Pointers to resource record contents
typedef struct {
    uchar *name;
    dns_ansdata_t *resource;
    uchar *rdata;
} dns_answer_t;
 
// Structure of a Query
typedef struct {
    uchar *name;
    dns_qdata_t *ques;
} dns_question_t;



typedef struct {
    struct sockaddr_in  addr_ip4;
    struct sockaddr_in6 addr_ip6;
    bool ipv4;
} serv_addr_t;


// Convert domain name to IP address using getaddrinfo()
int dns_domain_to_ip(const char* server_domain_name, char* server_ip, bool* ip_type4);

// Send DNS query
int dns_send_question(int sock_fd, serv_addr_t serv, char* domain_or_ip, bool recursion_desired, uint16_t query_type);

// Receive all DNS answers
int dns_receive_answers(int sock_fd, serv_addr_t serv);

#endif // !__DNS_PACKET_H__