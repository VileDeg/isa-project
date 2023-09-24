#include <stdio.h>
#include <stdbool.h>

struct Args {
    bool i_flag; // interface flag (-i or --interface)
    std::string interface;
    int port;
    // Protocol flags
    bool tcp;
    bool udp;
    bool arp;
    bool icmp4;
    bool icmp6;
    bool ndp;
    bool igmp;
    bool mld;
    
    bool n_flag; // num flag (-n or --num)
    int num;

    Args() : i_flag(false), interface(""), port(-1), 
        tcp(false), udp(false), arp(false), icmp4(false), 
        icmp6(false), ndp(false), igmp(false), mld(false),
        n_flag(false), num(1) 
    {}

    int parse(int argc, char** argv);

    // Builds a filter string for pcap_compile
    std::string assemble_filter();
    
    int num_of_protocols_set() const {
        return tcp + udp + arp + icmp4 + icmp6 + ndp + igmp + mld;
    }

    bool just_print_interfaces() const {
        bool other_not_set = port == -1 && 
            !tcp && !udp && !arp && !icmp4 && !icmp6 && 
            !ndp && !igmp && !mld && !n_flag;

        /* If -i or --interface is set, but no other flags are set
           or if there were no flags set at all */
        return (!i_flag && other_not_set) || (i_flag && interface == "" && other_not_set);
    }
};