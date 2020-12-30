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
  char * content = get_option_item(options, "content", size_of_options);
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

void check_xss(ETHER_Frame *frame, Rule rule)
{
  if(frame->data.transport_type == TCP)
  {
    // check if it's HTTP by checking for HTTP string in the payload
    if(strstr(frame->data.tcp_data.data, "HTTP") != NULL)
    {
      if(match_ports_and_ip_tcp(frame, rule) == 4)
      {
        char * payload = strtok((char *) frame->data.tcp_data.data, " ");
        payload = strtok(NULL, " ");
        printf("%s\n", payload);
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
      // check if it's HTTP by checking for HTTP string in the payload
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

void check_ftp(ETHER_Frame *frame, Rule rule)
{
  if(frame->ethernet_type == IPV4)
  {
    if(frame->data.transport_type == TCP)
    {
      if(frame->data.tcp_data.source_port == 21 || frame->data.tcp_data.source_port == 20 || frame->data.tcp_data.destination_port == 21 || frame->data.tcp_data.destination_port == 20)
      {
        // Using the tcp function since ftp uses tcp exclusively
        if(match_ports_and_ip_tcp(frame, rule) == 4)
        {
          int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
          check_option(frame, rule.options, size_of_options);
        }
      }
    }
  }
}

void check_flood(ETHER_Frame * frame, Rule rule, int * syn_flood_seq, int syn_flood_seq_size)
{
  int nb_connection = 0;
  for(int i = 0; i < syn_flood_seq_size; i++)
  {
    if(syn_flood_seq[i] != 0)
    {
      nb_connection++;
    }
  }
  // Consider a syn flood when more than 10 connections are open
  if(nb_connection > 10 && match_ports_and_ip_tcp(frame, rule) == 4)
  {
    int size_of_options = sizeof(rule.options)/sizeof(Rule_option);
    check_option(frame, rule.options, size_of_options);
    syslog(LOG_SYSLOG, "%s", "DDOS ATTACK");
  }
}

int check_syn_flood(ETHER_Frame *frame, Rule rule, int * syn_flood_seq, int syn_flood_seq_size, int next_free_pos)
{
  if(frame->data.transport_type == TCP)
  {
    // ACK = 0x10 -> decimal: 16
    // check for ACK and check if its ack number is in the list
    // means the 3 way handshake is done
    if(frame->data.tcp_data.th_flag == 16)
    {
      for(int i=0; i < syn_flood_seq_size; i++)
      {
        if(syn_flood_seq[i] == frame->data.tcp_data.ack_number)
        {
          syn_flood_seq[i] = 0;
        }
      }
    }
    // Using 18 for SYN-ACK flag 0x12 = 18
    // check for syn-ack and add the sequence number to the list
    if(frame->data.tcp_data.th_flag == 18)
    {
      syn_flood_seq[next_free_pos] = frame->data.tcp_data.sequence_number+1;
      next_free_pos++;
    }
    check_flood(frame, rule, syn_flood_seq, syn_flood_seq_size);
  }
  return next_free_pos;
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
