#ifndef RULE_C
#define RULE_C
#include "rule.h"

char * get_option_item(Rule_option * options, char * key, int option_size)
{
  for(int i = 0; i < option_size; i++)
  {
    if(strcmp(key, options[i].key) == 0)
    {
      return options[i].value;
    }
  }
  return NULL;
}
#endif
