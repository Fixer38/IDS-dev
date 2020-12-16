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

int match_ports_and_ip(ETHER_Frame *frame, Rule rule)
{
  int field_matches = 0;
  field_matches = field_matches + match_ip(frame->data.source_ip, rule.source_ad);
  field_matches = field_matches + match_ip(frame->data.destination_ip, rule.destination_ad);
  field_matches = field_matches + match_port(frame->data.tcp_data.source_port, rule.source_po);
  field_matches = field_matches + match_port(frame->data.tcp_data.destination_port, rule.destination_po);
  return field_matches;
}

void check_http(ETHER_Frame *frame, Rule rule)
{
  if(frame->ethernet_type == IPV4)
  {
    if(frame->data.transport_type == TCP)
    {
      if(strstr(frame->data.tcp_data.data, "HTTP") != NULL)
      {
        if(match_ports_and_ip(frame, rule) == 4)
        {
          int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
          for(int i = 0; i < size_of_options; i++)
          {
            if(strcmp(rule.options[i].key, "msg") == 0)
            {
              printf("%s\n", rule.options[i].value);
            }
          }
          printf("%ld", sizeof(rule.options) / sizeof(Rule_option));
        }
        else {
          printf("Packet discarded");
        }
      }
    }
  }
}

void check_tcp(ETHER_Frame *frame, Rule rule)
{
  if(frame->data.transport_type == TCP)
  {
    if(match_ports_and_ip(frame, rule) == 4)
    {
      int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
      for(int i = 0; i < size_of_options; i++)
      {
        if(strcmp(rule.options[i].key, "msg") == 0)
        {
          printf("%s\n", rule.options[i].value);
        }
      }
      printf("Packet TCP est flag par la règle\n");
    }
    else {
      printf("Packet discarded");
    }
  }
}

void check_udp(ETHER_Frame *frame, Rule rule)
{
  if(frame->data.transport_type == UDP)
  {
    if(match_ports_and_ip(frame, rule) == 4)
    {
      int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
      for(int i = 0; i < size_of_options; i++)
      {
        if(strcmp(rule.options[i].key, "msg") == 0)
        {
          printf("%s\n", rule.options[i].value);
        }
      }
      printf("Packet UDP flagged by rule\n");
    }
    else {
      printf("Packet Discarded");
    }
  }
}
#endif
