#ifndef __DNS_PACKET_H__
#define __DNS_PACKET_H__

// Inspired by:
// https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
typedef struct {
    uint16_t id; // identification number
 
    uint8_t  rd :1; // recursion desired
    uint8_t  tc :1; // truncated message
    uint8_t  aa :1; // authoritive answer
    uint8_t  opcode :4; // purpose of message
    uint8_t  qr :1; // query/response flag

    uint8_t  rcode :4; // response code
    uint8_t  cd :1; // checking disabled
    uint8_t  ad :1; // authenticated data
    uint8_t  z :1; // its z! reserved
    uint8_t  ra :1; // recursion available
 
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
} dns_header_t;
 
//Constant sized fields of query structure
typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_qdata_t;
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
} dns_ansdata_t;
#pragma pack(pop)
 
//Pointers to resource record contents
typedef struct {
    uchar *name;
    dns_ansdata_t *resource;
    uchar *rdata;
} dns_answer_t;
 
//Structure of a Query
typedef struct {
    uchar *name;
    dns_qdata_t *ques;
} dns_question_t;


void dns_answer_free();

int dns_send_question(int sock_fd, struct sockaddr_in addr, char* domain_name_to_resolve, bool recursion_desired, uint16_t record_type);

int dns_receive_answers(int sock_fd, struct sockaddr_in addr, char* domain_name_to_resolve);

#endif // !__DNS_PACKET_H__