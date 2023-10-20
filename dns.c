/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#include "base.h"
#include "args.h"
#include "dns_packet.h"

int sock_fd = -1;

void terminate(int code) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }
    exit(code);
}   

void signal_handler(int signal) {
#if VERBOSE
    printf("\nSignal (%d) received. Terminating...", signal);
#endif
    terminate(0);
}

void print_help() {
    printf(HELP_MESSAGE);
}

int main(int argc, char* argv[]) 
{
    #ifdef DEBUG
        // Disable buffering
        setbuf(stdout, NULL);
    #endif

    signal(SIGINT , signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    args_t args;
    memset(&args, 0, sizeof(args_t));
    args.query_type = T_A;
    args.port = DEFAULT_PORT;
    args.port_str[0] = '5';
    args.port_str[1] = '3';

    int ret = parse_args(argc, argv, &args);
    if (ret > 0) {
        terminate(1);
    } else if (ret < 0) {
        print_help();
        terminate(0);
    }

    char server_ip[INET6_ADDRSTRLEN];
    //dns_domain_to_ip((char*)args.server_name, args.port_str, server_ip);
    dns_domain_to_ip((char*)args.server_name, server_ip);

    sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sock_fd < 0) {
        perror("Failed creatng socket.");
        terminate(1);
    }

    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(args.port);
    addr.sin_addr.s_addr = inet_addr(server_ip); // Convert dns server address to binary network format

    if (dns_send_question(sock_fd, addr, args.address_str, args.recursion_desired, args.query_type) != 0) {
        terminate(1);
    }

    if (dns_receive_answers(sock_fd, addr, args.address_str) != 0) {
        terminate(1);
    }

    terminate(0);
}

