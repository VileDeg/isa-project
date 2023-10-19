#ifndef __ARGS_H__
#define __ARGS_H__

#include <stdbool.h>
#include <stdint.h>

#define MAX_DOMAIN_NAME_LEN 255
#define PORT_STR_LEN 5
#define MAX_ADDR_LEN 65536

typedef struct {
    bool recursion_desired;
    uint16_t query_type;
    unsigned char server_name[MAX_DOMAIN_NAME_LEN+1];
    uint16_t port;
    char port_str[PORT_STR_LEN+1];
    char address_str[MAX_ADDR_LEN];
} args_t;


int parse_args(int argc, char** argv, args_t* outa);

#endif // !__ARGS_H__