#ifndef MY_MAC_H
#define MY_MAC_H

#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdint.h>

#include <pcap.h>


#endif // MY_MAC_H

#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct my_ether_header{
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
};

struct my_my_arphdr{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
};

struct my_ether_arp{
    struct my_my_arphdr ea_hdr;

    uint8_t arp_sha[ETH_ALEN];
    uint8_t arp_spa[4];
    uint8_t arp_tha[ETH_ALEN];
    uint8_t arp_tpa[4];
};

#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op


struct arp_packet{
    struct my_ether_header my_ether_header;
    struct my_ether_arp my_ether_arp;

};

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};



char * my_mac();
char * my_ip();
