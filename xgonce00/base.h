/* 
 * @author Vadim Goncearenco (xgonce00)
 */

#ifndef __BASE_H__
#define __BASE_H__

#define _POSIX_C_SOURCE 200112L // Required for 'getaddrinfo' and other...

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> // fclose
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h> // for timeval
#include <netdb.h>

#ifdef DEBUG
    #define VERBOSE 1
#else    
    #define VERBOSE 0
#endif    

#define N_QUESTIONS 1 // Send 1 question

#define BUFFER_SIZE 65536

#define DEFAULT_PORT 53


#define T_A 1 // Ipv4 record
#define T_CNAME 5 // Canonical Name record
#define T_AAAA 28 // Ipv6 record
#define T_NS 2 // Nameserver
#define T_SOA 6 // Start of authority zone
#define T_PTR 12 // Domain name pointer
#define T_MX 15 // Mail server

typedef unsigned char uchar;

#define HELP_MESSAGE \
    "NAME \n\
    dns - DNS resolver \n\
    \n\
    SYNOPSIS\n\
        dns [-r] [-x|-6] -s server [-p port] domain|address\n\
        dns -h\n\
    \n\
    DESCRIPTION\n\
        dns is a simple DNS resolver that can handle both IPv4 and IPv6\n\
        addresses. Additionally, it has the capability to perform\n\
        reverse queries and can query any DNS server. It supports\n\
        recursive queries and can also communicate with DNS servers using\n\
        IPv6 or a non-standard port. \n\
    \n\
    OPTIONS\n\
        -r\n\
            Recursive query. If the DNS server does not have the answer, it will recursively query other DNS servers.\n\
        \n\
        -x\n\
            Reverse DNS lookup. The address is interpreted as an IPv4/IPv6 address\n\
            and a PTR query is sent.\n\
        \n\
        -6\n\
            Send AAAA query to receive IPv6 address.\n\
        \n\
        -s server\n\
            DNS server domain name or IPv4/IPv6 address to send a query to.\n\
        \n\
        -p port\n\
            Port to use when querying the DNS server. Default is 53.\n\
        \n\
        -h\n\
            Print help and exit.\n\
        \n\
        domain|address\n\
            Domain name to query or IPv4/IPv6 address to reverse query.\n"

#endif // !__BASE_H__