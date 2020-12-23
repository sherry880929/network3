//每個封包一行
//封包時間 來源目標MAC Ethertype
//IP的話 來源目標IP位置
//TCP UDP port
//ARP ICMP

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>

//ip_total bonus
int ip_total = 0;
int ip6_total = 0;
//int len = 0;



struct ip_pair
{
    char src[50];
    char dst[50];
    int cnt;
};

void print_macaddr(unsigned char *mac_addr)
{
    int i;
    for(i=0 ; i<6 ; i++){
        printf("%02x ", *(mac_addr + i));
    }
    printf("\n");
}

void dump_udp(u_int32_t length,const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    u_int16_t sur_port = ntohs(udp->uh_sport);
    u_int16_t des_port = ntohs(udp->uh_dport);
    printf("Source Port: %d\n",sur_port);
    printf("Destination Port: %d\n",des_port);

}

void dump_tcp(u_int32_t length,const u_char *content){
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    u_int16_t sur_port = ntohs(tcp->th_sport);
    u_int16_t des_port = ntohs(tcp->th_dport);
    printf("Source Port: %d\n",sur_port);
    printf("Dest Port: %d\n",des_port);
}

void dump_ip(u_int32_t length,const u_char *content,struct ip_pair arr[]){
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;

    //print IP source & destination address
    printf("Source IP Address: ");
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, str, sizeof(str));
    printf("%s\n",str);
    printf("Dest  IP Address: ");
    static char str1[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_dst, str1, sizeof(str));
    printf("%s\n",str1);

    ip_total++;

    //check ip
    switch (protocol) 
    {
        case IPPROTO_UDP:
            printf("UDP packet:\n");
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            printf("TCP packet:\n");
            dump_tcp(length, content);
            break;

        case IPPROTO_ICMP:
            printf("ICMP packet:\n");
    }

}
//ipv6
void dump_ipv6(u_int32_t length,const u_char *content,struct ip_pair arr[]){

    char sourIP6[INET6_ADDRSTRLEN];
    char destIP6[INET6_ADDRSTRLEN];
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(content + ETHER_HDR_LEN);
   
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), sourIP6, INET6_ADDRSTRLEN);
    printf("Source IP Addr: %s\n", sourIP6);

    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);
    printf("Destination IP Addr: %s\n", destIP6);
    
    
    ip6_total++;
    int nextheader = ipv6_header->ip6_nxt;
   

    switch (nextheader) 
    {
        case IPPROTO_UDP:
            printf("UDP packet:\n");
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            printf("TCP packet:\n");
            dump_tcp(length, content);
            break;
        case IPPROTO_ICMP:
            printf("ICMP packet:\n");
            break;
    }
    
}


int main(int argc , char *argv[]){
    pcap_t *handler = NULL;
    struct ip_pair arr[1000];
    char errbuf[PCAP_ERRBUF_SIZE];
    int num = 1;
    int flag = 0;
    int lenflag = 0;

    //argv[1] = 已錄好pcap檔
    handler = pcap_open_offline(argv[1], errbuf);
    if(!handler)
    {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        exit(1);
    }

    while(num)
    {
        struct pcap_pkthdr *header = NULL;
        const u_char *content = NULL;
        
	int ret;
	
	//catch package
	//success return 1 , failed return -1 , timeout return 0 , no package return -2
        ret = pcap_next_ex(handler, &header, &content);
        
        if(ret == 1)
	{
            u_int16_t type;
            unsigned short ethernet_type = 0;
            struct ether_header *ethernet = (struct ether_header *)content;
            printf("--------------------\n");

            //print time
	    struct tm *ltime;
    	    char timestr[21];
            memset(timestr,0,sizeof(timestr));
            ltime = localtime(&header->ts.tv_sec);
            strftime(timestr, sizeof timestr, "%Y-%m-%e:%H:%M:%S", ltime);
            printf("Time: %s\n",timestr);

            // print mac source&destination address
            unsigned char *mac_addr = NULL;
            mac_addr = (unsigned char *)ethernet -> ether_shost;
            printf("Mac Source Address: ");
            print_macaddr(mac_addr);
            mac_addr = (unsigned char *)ethernet -> ether_dhost;
            printf("Mac Destination Address: ");
            print_macaddr(mac_addr);

            //print type
            ethernet_type = ntohs(ethernet->ether_type);
            printf("Ether type : ");
            printf("%2x\n",ethernet->ether_type);
	    switch(ethernet_type)
            {
	            case ETHERTYPE_IP:
                    //IP(IPv4)
                    printf("IP:\n");
                    dump_ip(header->caplen,content,arr);
                    break;
                    
		    case ETHERTYPE_IPV6:
		    //IPv6
                    printf("IPv6\n");
                    dump_ipv6(header->caplen,content,arr);
                    break;

                    case ETHERTYPE_ARP :
                        printf("ARP\n");
                        break;
            }
            printf("Length: %d bytes\n", header->len);
            printf("--------------------\n");
        }
        //ret == -1 pcap err
        else if(ret == -1) fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handler));
        else if(ret == -2) break;

        if(flag) num--;
    }

    printf("IP Package: %d\n",ip_total);
    //free
    pcap_close(handler);
    return 0;
}
