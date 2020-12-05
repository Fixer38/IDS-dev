#include "populate.h"

struct ids_rule
{
  char * action;
  char * protocol;
  char source_ad[IP_ADDR_LEN_STR];
  int source_po;
  char * direction;
  char destination_ad[IP_ADDR_LEN_STR];
  int destination_po;
} typedef Rule;

struct rule_option
{
  char * key;
  char * value;
} typedef Rule_option;

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame)
{
}


void read_rules(FILE * file, Rule *rules_ds, int count)
{

}


void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)

{
  ETHER_Frame custom_frame;
  populate_packet_ds(header, packet, &custom_frame);
}

int main(int argc, char *argv[]) 
{
        
        char *device = "wlp5s0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 10;

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;
}
