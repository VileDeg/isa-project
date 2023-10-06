#include "base.h"
#include "args.h"

#define MIN_PORT 0
#define MAX_PORT 65535

typedef struct {
    bool r, x, _6, s, p;
} flags_t;

int parse_args(int argc, char** argv, args_t* outa) 
{
    flags_t flags;
    memset(&flags, 0, sizeof(flags_t));

    bool server_set  = false;
    bool address_set = false;

    char flag = '\0';
    for (int i = 1; i < argc; ++i) { // argv[0] is program name
        char* a = argv[i];
        char c = a[0];
        
        
        if (c == '-') {
            flag = a[1];

            switch (flag)
            {
            case 'r': // -r
                if (flags.r) {
                    sprintf(stderr, "Duplicated flag: -%c\n", flag);
                    return 1; // Duplicated flag;
                }
                outa->recursion_desired = true;
                flags.r = true;
                break;
            case 'x': // -x
                if (flags.x) {
                    sprintf(stderr, "Duplicated flag: -%c\n", flag);
                    return 1; // Duplicated flag;
                }
                outa->reverse_call = true;
                flags.x = true;
                break;
            case '6': // -6
                if (flags._6) {
                    sprintf(stderr, "Duplicated flag: -%c\n", flag);
                    return 1; // Duplicated flag;
                }
                flags._6 = true;
                outa->type_ipv6 = true;
                break;
            case 's':
                if (flags.s) {
                    sprintf(stderr, "Duplicated flag: -%c\n", flag);
                    return 1; // Duplicated flag;
                }
                flags.s = true;
                break;
            case 'p':
                if (flags.p) {
                    sprintf(stderr, "Duplicated flag: -%c\n", flag);
                    return 1; // Duplicated flag;
                }
                flags.p = true;
                if (!server_set) { // port name encountered before serv name
                    return 1;
                }
                
                break;
            default:
                return 1;
            }
        } else {
            if (flag == 's') {
                if (!server_set) {
                    memcpy(outa->server_name, a, strlen(a));
                    server_set = true;
                } else {
                    memcpy(outa->address_str, a, strlen(a));
                    //outa->address_str[strlen(a)] = '\0';
                    address_set = true;
                }
            } else if (flag == 'p') { 
                outa->port = atoi(a);
                if (errno == ERANGE || errno == EINVAL) {
                    fprintf(stderr, "Invalid port value.\n");
                    return 1;
                }
                if (outa->port < MIN_PORT || outa->port > MAX_PORT) {
                    fprintf(stderr, "Port must be in range %d-%d.\n", MIN_PORT, MAX_PORT);
                    return 1;
                }
                memcpy(outa->port_str, a, strlen(a));
            } else {
                return 1;
            }
        }
    }

    if (!server_set || !address_set) { // mandatory options not set
        return 1;
    }

    //TODO validate address
    
    return 0;
}
