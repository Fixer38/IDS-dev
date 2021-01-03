#include <stdio.h>
#include "populate.h"

void generate_ip(unsigned int ip, char ip_addr[])
{
  unsigned char bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;
  snprintf(ip_addr,IP_ADDR_LEN_STR,
      "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]); 
}

void print_payload(int payload_length, unsigned char *payload)
{
  if (payload_length > 0) 
  {
    const u_char *temp_pointer = payload;
    int byte_count = 0;
    while (byte_count++ < payload_length) 
    {
      printf("%c", (char)*temp_pointer);
      temp_pointer++;
    }
    printf("\n");
  }
}


int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet, ETHER_Frame *custom_frame)
{
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  //const struct sniff_arp *arp;
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const struct sniff_udp *udp;
  unsigned char *payload; /* Packet payload */

  u_int size_ip;
  u_int size_tcp;
  u_int size_udp;

  ethernet = (struct sniff_ethernet*)(packet);
  //ETHER_Frame custom_frame;
  char src_mac_address[ETHER_ADDR_LEN_STR];
  char dst_mac_address[ETHER_ADDR_LEN_STR];
  custom_frame->frame_size = header->caplen;
  // Convert unsigned char MAC to string MAC
  for(int x=0;x<6;x++)
  {
    snprintf(src_mac_address+(x*2),ETHER_ADDR_LEN_STR,
          "%02x",ethernet->ether_shost[x]);
    snprintf(dst_mac_address+(x*2),ETHER_ADDR_LEN_STR,
          "%02x",ethernet->ether_dhost[x]);
  }

  strcpy(custom_frame->source_mac,src_mac_address);
  strcpy(custom_frame->destination_mac, dst_mac_address);

  if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP) 
  {
    custom_frame->ethernet_type = ARP;
    printf("\nARP packet: %d\n",custom_frame->ethernet_type);
    /*arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
    ARP_FRAME custom_frame;
    char custom_target_mac[ETHER_ADDR_LEN_STR];
    char custom_source_mac[ETHER_ADDR_LEN_STR];
    for(int i=0;i<6;i++)
    {
      printf("custom target mac: %02X", arp->tha[i]);
    }
    for(int x=0;x<6;x++)
    {
      snprintf(custom_source_mac+(x*2), ETHER_ADDR_LEN_STR,
          "%02x",arp->sha[x]);
      snprintf(custom_target_mac+(x*2),ETHER_ADDR_LEN_STR,
          "%02x",arp->tha[x]);
    }
    printf("custom target and source mac: %s", custom_target_mac);*/
  }

  if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) 
  {
    custom_frame->ethernet_type = IPV4;
    printf("\nIPV4 packet: %d\n",custom_frame->ethernet_type);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    IP_Packet custom_packet;
    char src_ip[IP_ADDR_LEN_STR];
    char dst_ip[IP_ADDR_LEN_STR];
    generate_ip(ip->ip_src.s_addr,src_ip);
    generate_ip(ip->ip_dst.s_addr,dst_ip);

    strcpy(custom_packet.source_ip,src_ip);
    strcpy(custom_packet.destination_ip, dst_ip);
    custom_packet.transport_type = NONE;

    size_ip = IP_HL(ip)*4;

    if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return ERROR;
    }

    if((int)ip->ip_p==UDP_PROTOCOL)
    {
      printf("\nUDP Handling\n");
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
      UDP_Packet custom_datagram;
      size_udp = ntohs(udp->data_length);

      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);

      custom_datagram.source_port = ntohs(udp->sport);
      custom_datagram.destination_port = ntohs(udp->dport);
      custom_datagram.data = payload;
      int payload_length = ntohs(ip->ip_len) - (size_ip + 8);
      custom_datagram.data_length = payload_length;

      custom_packet.udp_data = custom_datagram;
      custom_packet.transport_type = UDP;
      custom_frame->data = custom_packet;
    }
    if((int)ip->ip_p==TCP_PROTOCOL)
    {
      printf("\nTCP Handling\n");
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      TCP_Segment custom_segment;

      size_tcp = TH_OFF(tcp)*4;

      if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return ERROR;
      }
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

      int payload_length = (header->caplen)-SIZE_ETHERNET-size_ip-size_tcp;
      custom_segment.source_port = ntohs(tcp->th_sport);
      custom_segment.destination_port = ntohs(tcp->th_dport);
      custom_segment.th_flag = (int)tcp->th_flags;
      custom_segment.sequence_number = tcp->th_seq;
      custom_segment.data = payload;
      custom_segment.data_length = payload_length;

      custom_packet.tcp_data = custom_segment;
      custom_packet.transport_type = TCP;
      custom_frame->data = custom_packet;
    }
  }
  return 0;
}

