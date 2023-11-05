/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#ifndef __ARGS_H__
#define __ARGS_H__

#include <stdbool.h>
#include <stdint.h>

#define MAX_DOMAIN_STR_LEN 254
#define MAX_PORT_STR_LEN 6

typedef struct {
    bool recursion_desired;
    uint16_t query_type;
    unsigned char server_name[MAX_DOMAIN_STR_LEN];
    uint16_t port;
    char port_str[MAX_PORT_STR_LEN];
    char address_str[MAX_DOMAIN_STR_LEN];
} args_t;


int parse_args(int argc, char** argv, args_t* outa);

#endif // !__ARGS_H__