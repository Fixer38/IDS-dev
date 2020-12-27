#ifndef PROTOCOL_C
#define PROTOCOL_C
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
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

int match_ports_and_ip_tcp(ETHER_Frame *frame, Rule rule)
{
  int field_matches = 0;
  field_matches = field_matches + match_ip(frame->data.source_ip, rule.source_ad);
  field_matches = field_matches + match_ip(frame->data.destination_ip, rule.destination_ad);
  field_matches = field_matches + match_port(frame->data.tcp_data.source_port, rule.source_po);
  field_matches = field_matches + match_port(frame->data.tcp_data.destination_port, rule.destination_po);
  return field_matches;
}

int match_ports_and_ip_udp(ETHER_Frame *frame, Rule rule)
{
  int field_matches = 0;
  field_matches = field_matches + match_ip(frame->data.source_ip, rule.source_ad);
  field_matches = field_matches + match_ip(frame->data.destination_ip, rule.destination_ad);
  field_matches = field_matches + match_port(frame->data.udp_data.source_port, rule.source_po);
  field_matches = field_matches + match_port(frame->data.udp_data.destination_port, rule.destination_po);
  return field_matches;
}

void check_option(ETHER_Frame * frame, Rule_option * options, int size_of_options)
{
  char * msg = get_option_item(options, "msg", size_of_options);
  char * content = get_option_item(options, " content", size_of_options);
  if(msg != NULL)
  {
    if(content == NULL)
    {
      syslog(LOG_INFO, "%s", msg);
    }
    else
    {
      if(frame->data.transport_type == UDP)
      {
        if(strstr(frame->data.udp_data.data, content) != NULL)
        {
          syslog(LOG_INFO, "%s", msg);
        }
      }
      else
      {
        if(strstr(frame->data.tcp_data.data, content) != NULL)
        {
          syslog(LOG_INFO, "%s", msg);
        }
      }
    }
  }
}
void check_http(ETHER_Frame *frame, Rule rule)
{
  if(frame->ethernet_type == IPV4)
  {
    if(frame->data.transport_type == TCP)
    {
      if(strstr(frame->data.tcp_data.data, "HTTP") != NULL)
      {
        if(match_ports_and_ip_tcp(frame, rule) == 4)
        {
          int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
          check_option(frame, rule.options, size_of_options);
        }
      }
      else
      {
        if(frame->data.tcp_data.source_port == 443 || frame->data.tcp_data.destination_port == 443)
        {
          printf("Packet crypté.\n");
        }
      }
    }
  }
}

void check_tcp(ETHER_Frame *frame, Rule rule)
{
  if(frame->data.transport_type == TCP)
  {
    if(match_ports_and_ip_tcp(frame, rule) == 4)
    {
      int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
      check_option(frame, rule.options, size_of_options);
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
    if(match_ports_and_ip_udp(frame, rule) == 4)
    {
      int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
      check_option(frame, rule.options, size_of_options);
    }
    else {
      printf("Packet Discarded");
    }
  }
}
#endif
