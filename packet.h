#ifndef PACKET_H
#define PACKET_H
#pragma pack(push, 1);
#endif // PACKET_H
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <time.h>


struct E_header{
    uint8_t dMac[6];
    uint8_t sMac[6];
    uint16_t etherType;

};

struct IP_header{
    uint8_t target_ip_address[4];
    uint8_t sender_ip_address[4];
    //uint8_t Proto;

};

struct TCP_header{
    uint8_t sPort[2];
    uint8_t dPort[2];
};

struct arp_packet{
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ether_type;
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint8_t target_hardware_addr[6];
    uint8_t target_ip_address[4];
    uint8_t sender_hardware_addr[6];
    uint8_t sender_ip_address[4];

};


uint32_t ntohl(uint32_t n){
        return (((n & 0xff000000) >> 24) | ((n & 0x00ff0000) >> 8) | ((n & 0x0000ff00 << 8) | ((n & 0x000000ff) << 24)));
}

uint16_t ntohs(uint16_t n){
    return ((n >> 8) | (n << 8));
}

