#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "populate.h"
#include "rule.h"

int match_ip(char ip_from_frame[IP_ADDR_LEN_STR], char ip_from_rule[IP_ADDR_LEN_STR])
{
  if(ip_from_frame == ip_from_rule || strcmp(ip_from_rule, "any") == 0)
  {
    return 1;
  }
  return 0;
}

int match_port(int port_from_frame, char port_from_rule[5])
{
  if(strcmp(port_from_rule, "any") == 0)
  {
    return 1;
  }
  else if(atoi(port_from_rule) == port_from_frame)
  {
    return 1;
  }
  return 0;
}

void check_http(ETHER_Frame *frame, Rule rule)
{
  if(frame->ethernet_type == IPV4)
  {
    if(frame->data.transport_type == TCP)
    {
      if(strstr(frame->data.tcp_data.data, "HTTP") != NULL)
      {
        int field_matches = 0;
        field_matches = field_matches + match_ip(frame->data.source_ip, rule.source_ad);
        printf("field_matches: %d\n", field_matches);
        field_matches = field_matches + match_ip(frame->data.destination_ip, rule.destination_ad);
        printf("field_matches: %d\n", field_matches);
        field_matches = field_matches + match_port(frame->data.tcp_data.source_port, rule.source_po);
        printf("field_matches: %d\n", field_matches);
        field_matches = field_matches + match_port(frame->data.tcp_data.destination_port, rule.destination_po);
        printf("field_matches: %d\n", field_matches);
        if(field_matches == 4)
        {
          printf("%ld", sizeof(rule.options) / sizeof(Rule_option));
        }
        else {
          printf("Packet discarded");
        }
      }
    }
  }
}
#endif
