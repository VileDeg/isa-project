#include "args.h"

#include <getopt.h>

void print_usage(const char* name) {
    std::cout << std::endl;
    std::cout << "Usage:\n\n" << name << 
        " [-i interface | --interface interface] {-p port} " << 
        "{[--tcp|-t] [--udp|-u] [--arp] [--icmp] [--ndp] [--igmp] [--mld]} {-n num}\n" <<
        "Options:\n" <<
        "\t-i, --interface <interface>  Interface to listen on\n" <<
        "\t-p <port>                    Port to listen on\n" <<
        "\t-t, --tcp                    Listen on TCP\n" <<
        "\t-u, --udp                    Listen on UDP\n" <<
        "\t--arp                        Listen on ARP\n" <<
        "\t--icmp4                      Listen on ICMPv4\n" <<
        "\t--icmp6                      Listen on ICMPv6 (echo request/reply)\n" <<
        "\t--ndp                        Listen on NDP\n" <<
        "\t--igmp                       Listen on IGMP\n" <<
        "\t--mld                        Listen on MLD\n" <<
        "\t-n, --num <num>              Number of packets to listen on. Default (1)\n" <<
        "\t-h, --help                   Print this help message\n" <<
        "Order of arguments does not matter\n\n" <<
        name << "[-i|--interface] or " << name << "\n" <<
        "\tto print all available interfaces\n\n" <<
        "or\n\n" <<
        name << "[-help|-h]\n" <<
        "\tto print this help message\n\n" <<
    std::endl;
}

std::string Args::assemble_filter() {
        std::string filter = "";

        int nump = num_of_protocols_set();

        if (nump == 0) {
            return filter;
        }

        int tu = tcp + udp;
        if (port != -1) {
            // If tcp or udp is set, port only applies to tcp or udp
            filter += tu > 0 ? "(" : "";
            filter += "port " + std::to_string(port);
        }

        auto tu_wrappper = [&](const std::string& prstr) {
            filter += port != -1 ? " and " : "";
            filter += prstr;
            filter += port != -1 ? ")" : "";
        };

        if (tcp && udp) {
            tu_wrappper("(tcp or udp)");
        } else if (tcp) {
            tu_wrappper("tcp");
        } else if (udp) {
            tu_wrappper("udp");
        }
        
        if (nump == tu) { // Only tcp and udp flags were set
            return filter; 
        }

        if (port != -1) {
            if (tu > 0) {
                filter += ")";
            } else {
                /* If tcp or udp is not set, all packets with the port are captured,
                   so it's connected with an 'or' */
                filter += " or (";
            }
        }

        if (tu > 0) {
            filter += " or ";
        }

        int set = 0;
        auto or_wrapper = [&](const std::string& prstr) {
            filter += set > 0 ? " or " : "";
            filter += prstr;
            ++set;
        };
        
        if (arp) { // ARP
            or_wrapper("arp");
        }
        if (icmp4) { // ICMPv4
            or_wrapper("icmp");
        } 
        if (icmp6) { // ICMPv6 (request & reply)
            or_wrapper("(icmp6 and (icmp6[0] >= 128 and icmp6[0] <= 129))");
        } 
        if (ndp) { // NDP
            or_wrapper("(icmp6 and (icmp6[0] >= 133 and icmp6[0] <= 137))");
        } 
        if (igmp) { // IGMP
            or_wrapper("igmp");
        } 
        if (mld) { // MLDv1 and MLDv2
            or_wrapper("(icmp6 and (icmp6[0] >= 130 and icmp6[0] <= 132))");
        } 

        if (port != -1 && tu == 0) {
            filter += ")";
        }

        return filter;
    }

/* 
 * Because getopt_long() doesn't support optional arguments separated from flag (e.g. '-o arg'), we have to do it ourselves.
 * This macro checks if optional argument is present and if not, it checks if next argument is not a flag (starts with '-').
 * Inspired by https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/ [2]
 */
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

int Args::parse(int argc, char** argv) {
    // Interface has optional argument, so we will have to check if it's present
    const char* const short_opts = "i::p:tun:h";
    option long_opts[] = {
        {"interface", optional_argument, nullptr, 'i'},
        {"num", required_argument, nullptr, 'n'},
        {"tcp", no_argument, nullptr, 't'},
        {"udp", no_argument, nullptr, 'u'},
        {"arp", no_argument, nullptr, 'a'},
        {"icmp4", no_argument, nullptr, '4'},
        {"icmp6", no_argument, nullptr, '6'},
        {"ndp", no_argument, nullptr, 'N'},
        {"igmp", no_argument, nullptr, 'g'},
        {"mld", no_argument, nullptr, 'm'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, no_argument, nullptr, 0} // Must be null terminated
    };
    int opt = 0;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'i': // -i or --interface
                i_flag = true;
                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                    interface = optarg;
                }
                break;
            case 'p': // -p
                try {
                    port = std::stoi(optarg);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Invalid argument for -p: " << optarg << std::endl;
                    return 1;
                } catch (const std::out_of_range& e) {
                    std::cerr << "Argument for -p is out of range: " << optarg << std::endl;
                    return 1;
                }
                if (port < 0 || port > 65535) {
                    std::cerr << "Port must be in range 0-65535." << std::endl;
                    return 1;
                }
                break;
            case 't': // -t or --tcp
                tcp = true;
                break;
            case 'u': // -u or --udp
                udp = true;
                break;
            case 'a': // --arp
                arp = true;
                break;
            case '4': // --icmp4
                icmp4 = true;
                break;
            case '6': // --icmp6
                icmp6 = true;
                break;
            case 'N': // --ndp
                ndp = true;
                break;
            case 'g': // --igmp
                igmp = true;
                break;
            case 'm': // --mld
                mld = true;
                break;
            case 'n': // -n or --num
                n_flag = true;
                try {
                    num = std::stoi(optarg);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Invalid argument for -n: " << optarg << std::endl;
                    return 1;
                } catch (const std::out_of_range& e) {
                    std::cerr << "Argument for -n is out of range: " << optarg << std::endl;
                    return 1;
                }
                if (num < 1) {
                    std::cerr << "Number of packets must be greater than 0." << std::endl;
                    return 1;
                }
                break;
            case 'h': // -h or --help
                print_usage(argv[0]);
                return 2;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    return 0;
}
