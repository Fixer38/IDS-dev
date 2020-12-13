#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "populate.h"
#include "rule.h"

int matching_ip(char ip_from_frame[IP_ADDR_LEN_STR], char ip_from_rule[IP_ADDR_LEN_STR])
{
  if(ip_from_frame == ip_from_rule || strcmp(ip_from_rule, "any"))
  {
    return 1;
  }
  return 0;
}

int match_field(int field1, int field2)
{
  if(field1 == field2)
  {
    return 1;
  }
  return 0;
}

int match_port(int port_from_frame, char port_from_rule[5])
{
  if(strcmp(port_from_rule, "any"))
  {
    return 1;
  }
  else if(atoi(port_from_rule) == port_from_frame)
  {
    return 1;
  }
  return 0;
}

int match_all_ports(int port_from_frame_source, int port_from_frame_dest, char port_from_rule_source[5], char port_from_rule_dest[5])
{
  if(match_port(port_from_frame_source, port_from_rule_source) == 1 && match_port(port_from_frame_dest, port_from_rule_dest) == 1)
  {
    return 1;
  }
  return 0;
}

int check_http(ETHER_Frame *frame, Rule rule)
{
  int flag = 1;
  if(strstr((const char *) frame->data.data.data, "HTTP") != NULL)
  {
    printf("test de check_htp");
  }
}
#endif
