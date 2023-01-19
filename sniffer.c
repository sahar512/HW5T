#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <string.h>
struct appackets 
{

    uint16_t length;
    uint16_t cachecontrol;
    uint16_t padding;
    union {uint16_t saved:3,cflag:1,sflag:1,tflag:1,status:10,flag;};
    uint32_t unixtime;
};
struct sniff_ethernetheader
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
    
};
void write_data(FILE *fp, const uint8_t *data, uint16_t length)
{
    for (int i = 0; i < length; i++)
    {
        if (!(i & 15))
        {
            fprintf(fp, "\n%04X: ", i);
        }
        fprintf(fp, "%02X ", data[i]);
    }
    fprintf(fp, "\n\n");
}

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
     FILE *fp=fopen("324885417_325056695.txt","a+");    
    if(fp==NULL)
    {
        perror("can't open the file");
    }

    struct iphdr *iph=(struct iphdr *)(packet+sizeof(struct sniff_ethernetheader));
    char srcip[16],destip[16];
     inet_ntop(AF_INET,&(iph->daddr),srcip,INET_ADDRSTRLEN);
     inet_ntop(AF_INET,&(iph->saddr),destip,INET_ADDRSTRLEN);
     printf("NEW TCP PACKET :");
     fprintf(fp,"Source IP :%s \n ",destip);
     fprintf(fp,"Dest IP :%s \n ",srcip);
     struct tcphdr *tcph=(struct tcphdr*)(packet+sizeof(struct ethhdr)+iph->ihl*4);
     if (!tcph->psh)
        return;
     fprintf(fp,"Source port : %hu \n",ntohs(tcph->source));
     fprintf(fp,"Dest port : %hu \n ",ntohs(tcph->dest));
     struct appackets *pac=(struct appackets *)(packet +sizeof(struct sniff_ethernetheader)+iph->ihl*4+tcph->doff*4);


        fprintf(fp,"Times tamp : %ul \n ",ntohl(pac->unixtime));
        fprintf(fp,"Total length :%hu \n ",ntohs(pac->length));
        pac->flag=ntohs(pac->flag);
        fprintf(fp,"Cache flag : %hu \n ",(pac->flag >> 12) & 1);
        fprintf(fp,"Steps flag %hu \n",(pac->flag >> 11) & 1);
        fprintf(fp,"Type flag %hu \n ",(pac->flag >> 10) & 1);
        fprintf(fp,"Status code %hu \n ",pac->status);
        fprintf(fp,"Cache control : %hu \n ",ntohs(pac->cachecontrol));
        uint8_t datasaving[ntohs(pac->length)];
    memcpy(datasaving, (packet + sizeof(struct sniff_ethernetheader) + iph->ihl*4+ tcph->doff*4 + 12), ntohs(pac->length));
    if (ntohs(pac->length) >500)
    {
        fprintf(fp, "REQUEST:\n");
    }
    else
    {
        fprintf(fp, "RESPONSE:\n");
    }
    write_data(fp,datasaving,ntohs(pac->length));
fclose(fp);
    
}
int main()
{
    printf("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\");
    char *dev="lo";//the device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];//error string
    pcap_t *handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf); //session handle
    
    //open the session in promiscuous mode
    if (handle==NULL)
    {
        fprintf(stderr,"could not open device %s : %s \n",dev,errbuf);
        return (2);
    }

    char filter_exp[]="tcp";//the filter expression
    struct bpf_program fp;
    bpf_u_int32 mask;//our netmask
    bpf_u_int32 net=0; //our ip
    struct pcap_pkthdr header; //the header that pcap gives us 
    const u_char *packet; //the actual packet
    
    //find the properties for device
    if (pcap_lookupnet(dev,&net,&mask,errbuf)==-1)
    {
        fprintf(stderr,"couldn't get netmask for device :%s \n ",errbuf);
        net=0;
        mask=0;
    }
    
    //compile and apply the filter
    if (pcap_compile(handle,&fp,filter_exp,0,net)==-1)
    {
        fprintf(stderr,"could not parse filter %s:%s \n",filter_exp,pcap_geterr(handle));
        return(2);
    }
    
    if (pcap_setfilter(handle,&fp)==-1)
    {
        fprintf(stderr,"could not install filter %s:%s \n",filter_exp,pcap_geterr(handle));
        return(2);
    }

    //grap a packet
    pcap_loop(handle,-1,got_packet,NULL);
    //prints it's length
    printf("jacked a packet with length of [%d] \n ",header.len);
    //close the session
    pcap_close(handle);
    
}