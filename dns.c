/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#include "base.h"
#include "args.h"
#include "dns_packet.h"

int sock_fd = -1;

// Correctly terminates the program with the given exit code
void terminate(int code) 
{
    if (sock_fd >= 0) {
        close(sock_fd);
    }
    exit(code);
}   

void signal_handler(int signal) 
{
#if VERBOSE
    printf("\nSignal (%d) received. Terminating...", signal);
#endif
    terminate(0);
}

void print_help() 
{
    printf("\n" HELP_MESSAGE);
}

int create_socket(bool ip_type4) 
{
    // Create socket
    sock_fd = socket(ip_type4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (sock_fd < 0) {
        perror("Failed creatng socket.");
        return 1;
    }

    // Set socket timeout just in case
    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    
    if (setsockopt (sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed\n");
        return 1;
    }

    if (setsockopt (sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed\n");
        return 1;
    }
    return 0;
}

int get_server_address(serv_addr_t* serv, const char* server_name, uint16_t server_port)
{
    // Attempt to parse the address as IPv4
    if (inet_pton(AF_INET , (char*)server_name, &serv->addr_ip4.sin_addr) == 1) {
        serv->ipv4 = true;
        serv->addr_ip4.sin_family = AF_INET;
        serv->addr_ip4.sin_port = htons(server_port);
    } else if (inet_pton(AF_INET6, (char*)server_name, &serv->addr_ip6.sin6_addr) == 1) {
        serv->ipv4 = false;
        serv->addr_ip6.sin6_family = AF_INET6;
        serv->addr_ip6.sin6_port = htons(server_port);
    } else {
        // Convert server name to IP address using getaddrinfo()
        if (dns_domain_to_ip((char*)server_name, serv) != 0) {
            return 1;
        }

        if (serv->ipv4) {
            serv->addr_ip4.sin_port = htons(server_port);
        } else {
            serv->addr_ip6.sin6_port = htons(server_port);
        }
    }
    return 0;
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
        print_help();
        terminate(1);
    } else if (ret < 0) {
        print_help();
        terminate(0);
    }

    serv_addr_t serv;
    memset(&serv, 0, sizeof(serv_addr_t));

    if (get_server_address(&serv, (const char*)args.server_name, args.port) != 0) {
        terminate(1);
    }
    
    if (create_socket(serv.ipv4) != 0) {
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

