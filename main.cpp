#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// 여기에 header 부분 intnet.h 같은거 include 



typedef struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
} ethernet_hdr;


typedef struct libnet_ipv4_hdr
{

    u_int8_t ip_tos;       // type of service 
    u_int8_t dummy;
    u_int16_t ip_len;         // total length 
    u_int16_t ip_id;          // identification 
    u_int16_t ip_off;

    u_int8_t ip_ttl;          // time to live 
    u_int8_t ip_p;            // protocol 
    u_int16_t ip_sum;         // checksum 
    struct in_addr ip_src;
    struct in_addr ip_dst; // source and dest address 
} ipv4_hdr;

typedef struct libnet_tcp_hdr
{
    u_int16_t th_sport;       // source port 
    u_int16_t th_dport;       // destination port 
    u_int32_t th_seq;          // sequence number 
    u_int32_t th_ack;          // acknowledgement number 

    u_int16_t data_offset;
    u_int16_t th_win;         // window 
    u_int16_t th_sum;         // checksum 
    u_int16_t th_urp;         // urgent pointer 
} tcp_hdr;



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

uint32_t isTCP(const u_char* packet)
{
    ethernet_hdr* EH = (ethernet_hdr* )packet;
    ipv4_hdr* IH = (ipv4_hdr* )(packet + sizeof(ethernet_hdr));
    if( ntohs(EH->ether_type) == 0x0800 &&  IH -> ip_p == 0x06) // 이 부분 즉시값 쓰지 않고, 헤더 따로 include 해서 쓰기
    {
        return 1;
    }
    return 0;

}

void parse_packet(const u_char* packet);

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        if (!isTCP(packet))
        {
            printf("It is not TCP packet\n");
            continue;
        }
        
        parse_packet(packet);

    }

    pcap_close(handle);
}

void parse_packet(const u_char* packet)
{
    ethernet_hdr* EH = (ethernet_hdr*)packet;
    ipv4_hdr* IH = (ipv4_hdr*)(packet + sizeof(ethernet_hdr));
    uint32_t ip_hdr_len = ((IH -> ip_tos) & 0x0f) * 4;
    tcp_hdr* TH = (tcp_hdr*)(packet + sizeof(ethernet_hdr) + ip_hdr_len);
    uint32_t data_len = ntohs(IH -> ip_len) - ((TH -> data_offset & 0x00f0) >> 4 ) * 4 - ip_hdr_len;
    u_char* data = (u_char*)((u_char*)TH + ((TH -> data_offset & 0x00f0) >> 4) * 4 );
    
    // print mac address
    printf("src mac : ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x " ,EH -> ether_shost[i]);
    }
    printf("-> dest mac : ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x " ,EH -> ether_dhost[i]);
    }
    printf("\n");
    // print ip address
    u_char* ip1 = (u_char*)inet_ntoa(*(struct in_addr*)&IH -> ip_src); // inet_ntoa 말고 caller buffer 쓰는 inet_ntop 쓰기!!! 그게 더 reentering이 된다.
    printf("src ip : %s", ip1);
    u_char* ip2 = (u_char*)inet_ntoa(*(struct in_addr*)&IH -> ip_dst);
    printf(" -> dest ip : %s\n", ip2);

    // print port
    printf("src port : %d", ntohs(TH -> th_sport));
    printf(" -> dst port : %d\n", ntohs(TH -> th_dport));
    // print data 16 bytes
    if ( data_len > 16 )
    {
        data_len = 16;
    }
    printf("Data : ");
    if (data_len)
    {
        for (int i = 0; i < data_len; i++)
        {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }
    else
    {
        {
            printf("None!!\n");
        }
    }
    
    
}   
