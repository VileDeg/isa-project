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
#include <unistd.h> // Close file descriptor
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
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
#define T_NS 2 //Nameserver
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

typedef unsigned char uchar;

#endif // !__BASE_H__