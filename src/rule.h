#ifndef RULE_H
#define RULE_H
#include "populate.h"


struct rule_option
{
  char key[7];
  char value[50];
} typedef Rule_option;

struct ids_rule
{
  char action[6];
  char protocol[5];
  char source_ad[IP_ADDR_LEN_STR];
  char source_po[5];
  char direction[3];
  char destination_ad[IP_ADDR_LEN_STR];
  char destination_po[5];
  Rule_option options[2];
} typedef Rule;


char * get_option_item(Rule_option * options, char * key, int option_size);
#endif
