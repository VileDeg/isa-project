/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#include "base.h"
#include "args.h"
#include "dns_packet.h"

int sock_fd = -1;

// Correctly terminates the program with the given exit code
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

    // Parse arguments
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

    struct in_addr ipv4;
    struct in6_addr ipv6;

    char server_ip[INET6_ADDRSTRLEN];

    bool ip_type4 = true;

    // Attempt to parse the address as IPv4
    if (inet_pton(AF_INET , (char*)args.server_name, &ipv4) == 1) {
        ip_type4 = true;
        memcpy(server_ip, args.server_name, strlen((char*)args.server_name) + 1);
    } else if (inet_pton(AF_INET6, (char*)args.server_name, &ipv6) == 1) {
        ip_type4 = false;
        memcpy(server_ip, args.server_name, strlen((char*)args.server_name) + 1);
    } else {
        // Convert server name to IP address using getaddrinfo()
        if (dns_domain_to_ip((char*)args.server_name, server_ip, &ip_type4) != 0) {
            terminate(1);
        }
    }

    serv_addr_t serv;
    memset(&serv, 0, sizeof(serv_addr_t));

    serv.ipv4 = ip_type4;

    if (ip_type4) {
        serv.addr_ip4.sin_family = AF_INET;
        serv.addr_ip4.sin_port = htons(args.port);
         // Convert dns server address to binary network format
        serv.addr_ip4.sin_addr.s_addr = inet_addr(server_ip);
    } else {
        serv.addr_ip6.sin6_family = AF_INET6;
        serv.addr_ip6.sin6_port = htons(args.port);
         // Convert dns server address to binary network format
        if (inet_pton(AF_INET6, server_ip, &serv.addr_ip6.sin6_addr) != 1) {
            perror("Failed converting IPv6 address.");
            terminate(1);
        }
    }

    // Create socket
    sock_fd = socket(ip_type4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (sock_fd < 0) {
        perror("Failed creatng socket.");
        terminate(1);
    }

    // Send DNS query
    if (dns_send_question(sock_fd, serv, args.address_str, args.recursion_desired, args.query_type) != 0) {
        terminate(1);
    }

    // Receive all DNS answers
    if (dns_receive_answers(sock_fd, serv) != 0) {
        terminate(1);
    }

    terminate(0);
}

