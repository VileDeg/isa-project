<!-- soubor README obsahující jméno a login autora, datum vytvoření, krátký textový popis programu s případnými rozšířeními či omezeními, příklad spuštění a seznam odevzdaných souborů, -->

# dns
## About
```
NAME
    dns - DNS resolver

SYNOPSIS
    dns [-r] [-x|-6] -s server [-p port] domain|address
    dns -h

DESCRIPTION
    dns is a simple DNS resolver that can handle both IPv4 and IPv6 addresses. Additionally, it has the capability to perform reverse queries and can query any DNS server. It supports recursive queries and can also communicate with DNS servers using IPv6 or a non-standard port. 

OPTIONS
    -r
        Recursive query. If the DNS server does not have the answer, it will recursively query other DNS servers.
    
    -x
        Reverse query. The address is interpreted as an IPv4 address
        and the PTR record is queried. IPv6 addresses are not supported.
    
    -6
        Force IPv6. The query is sent to the DNS server using IPv6.

    -s server
        DNS server to query.
    
    -p port
        Port to use when querying the DNS server. Default is 53.

    -h
        Print help and exit.
    
    domain|address
        Domain name to query or IPv4 address to reverse query.

SIMPLE USAGE
    ./dns -r -s dns.google www.github.com
    Authoritative: No, Recursive: Yes, Truncated: No    
    Question section (1)
        www.github.com., A, IN
    Answer section (2)
        www.github.com., CNAME, IN, 3600, github.com.
    github.com., A, IN, 60, 140.82.121.3
    Authority section (0)
    Additional section (0)

    ./dns -r -x -s dns.google 140.82.121.3
    Authoritative: No, Recursive: Yes, Truncated: No    
    Question section (1)
        3.121.82.140.in-addr.arpa., PTR, IN
    Answer section (1)
        3.121.82.140.in-addr.arpa., PTR, IN, 2004, lb-140-82-121-3-fra.github.com.
    Authority section (0)
    Additional section (0)  

    ./dns -r -s kazi.fit.vutbr.cz www.fit.vut.cz
    Authoritative: No, Recursive: Yes, Truncated: No
    Question section (1)
        www.fit.vut.cz., A, IN
    Answer section (1)
        www.fit.vut.cz., A, IN, 14400, 147.229.9.26
    Authority section (0)
    Additional section (0)

    ./dns -r -s kazi.fit.vutbr.cz www.github.com
    Authoritative: No, Recursive: Yes, Truncated: No
    Question section (1)
        www.github.com., A, IN
    Answer section (2)
        www.github.com., CNAME, IN, 3600, github.com.
        github.com., A, IN, 60, 140.82.121.3
    Authority section (0)
    Additional section (0)

AUTHOR
    Vadim Goncearenco (xgonce00)

CREATION DATE
    13-11-2023
```
## Content
* [dns.c](dns.c) - Main program
* [base.h](base.h) - Base header file
* [args.c](args.c) - Arguments parsing
* [args.h](args.h) - Arguments header file
* [dns_packet.c](dns_packet.c) - DNS packet parsing
* [dns_packet.h](dns_packet.h) - DNS packet header file
* [test.py](test.py) - Test script
* [test_cases.json](test_cases.json) - JSON file with test cases
* [Makefile](Makefile) - Makefile
* [README.md](README.md) - This file
* [manual.pdf](manual.pdf) - Documentation
## Compilation
```
make
```
## Testing
```
make test
```
or
```
usage:
    python3 test.py [-h] [-d] [-i] [-v] input_file

positional arguments:
    input_file         input JSON file

options:
    -h, --help         show this help message and exit
    -d, --debug        run in debug mode (print all queries and responses)
    -i, --ignore-ipv6  ignore ipv6 tests (AAAA queries)
    -v, --ignore-vpn   ignore tests that require VUT FIT network VPN
```

Be aware that because the tests compare `./dns` output with output of `dig` command, some tests may sometimes fail because output of the `dig` command is not always the same. For example, for `www.github.com` it can sometimes return address that ends in a different number. So to ensure that the program works correctly, it is important to run the tests multiple times.