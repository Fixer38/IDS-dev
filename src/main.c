#include <ctype.h>
#include "protocol.c"
#include "rule.h"

#define syn_flood_seq_size 40

struct pcap_loop_arg
{
  int rules_ds_size;
  Rule * rules_ds;
} typedef Pcap_loop_arg;

void rule_matcher(Rule *rules_ds, int rules_ds_size, ETHER_Frame *frame)
{
  // Used to contain ack_number to match for after syn-ack
  // Theoretically contains opened connection on the server as it didn't receive the ack after ack-syn yet
  int syn_flood_seq[syn_flood_seq_size] = {0};
  // Used to determine the next free_position in the array
  int next_free_pos = 0;
  for(int i = 0; i < rules_ds_size; i++)
  {
    int size_of_options = sizeof(rules_ds[i].options)/sizeof(Rule_option);
    if(strcmp(rules_ds[i].protocol, "http") == 0)
    {
      char * rule_option_type = get_option_item(rules_ds[i].options, "type", size_of_options);
      if(rule_option_type && strcmp(rule_option_type, "xss") == 0)
      {
        check_xss(frame, rules_ds[i]);
      }
      else
      {
        check_http(frame, rules_ds[i]);
      }
    }
    else if(strcmp(rules_ds[i].protocol, "tcp") == 0)
    {
      //char * rule_option_type = get_option_item(rules_ds[i].options, "type", size_of_options);
      //if(rule_option_type && strcmp(rule_option_type, "syn flood") == 0)
      //{
        //next_free_pos = check_syn_flood(frame, rules_ds[i], syn_flood_seq, syn_flood_seq_size, next_free_pos);
      //}
      //else {
      check_tcp(frame, rules_ds[i]);
      //}
    }
    else if(strcmp(rules_ds[i].protocol, "udp") == 0)
    {
      check_udp(frame, rules_ds[i]);
    }
    else if(strcmp(rules_ds[i].protocol, "ftp") == 0)
    {
      check_ftp(frame, rules_ds[i]);
    }
  }
}

void reformat_option_value(Rule_option * options, int size_of_options)
{
  for(int i = 0; i < size_of_options; i++)
  {
    char * new_option_value = options[i].value;
    new_option_value++;
    memmove(options[i].value, options[i].value+1, strlen(options[i].value+1) + 1);
    options[i].value[strlen(options[i].value) - 1] = '\0';
    if(isspace(options[i].key[0]) != 0)
    {
      memmove(options[i].key, options[i].key+1, strlen(options[i].key+1) + 1);
    }
  }
}

void parse_rule(char line[100], Rule * rules_ds, int current_line)
{
  char options[50];
  sscanf(line, "%s %s %s %s %s %s %s (%[^)])",
        rules_ds[current_line].action, rules_ds[current_line].protocol, rules_ds[current_line].source_ad, rules_ds[current_line].source_po, rules_ds[current_line].direction, rules_ds[current_line].destination_ad, rules_ds[current_line].destination_po, options); 
  char * option_rest;
  char * option = strtok_r(options, ";", &option_rest);
  char * option_content;
  int current_option = 0;
  // using strtok_r to avoid deleting the content of the original rule line
  // Using strtok for the rest since the buffer of the origina rule line is saved inside &option_rest
  while(option != NULL) {
    option_content = strtok(option, ":");
    strcpy(rules_ds[current_line].options[current_option].key, option_content);
    option_content = strtok(NULL, ":");
    strcpy(rules_ds[current_line].options[current_option].value, option_content);
    option = strtok_r(option_rest, ";", &option_rest);
    current_option++;
  }
  int size_of_option = sizeof(rules_ds[current_line].options)/sizeof(Rule_option);
  reformat_option_value(rules_ds[current_line].options, size_of_option);
}

int increase_rules_ds(Rule **rules_ds, int nb_rule)
{
  Rule * temp = (Rule *) realloc(*rules_ds, (nb_rule * sizeof(Rule)));
  if(temp == NULL)
  {
    return 0;
  }
  else {
    *rules_ds = temp;
  }
  return 1;
}

int read_rules(FILE * file, Rule **rules_ds)
{
  int current_line = 0;
  char line[100];
  int alloc_success = 0;
  while(fgets(line, 100, file) != NULL)
  {
    parse_rule(line, *rules_ds, current_line);
    current_line++;
    alloc_success = increase_rules_ds(rules_ds, current_line+1);
    if(alloc_success == 0)
    {
      printf("Erreur lors de l'allocation de la mémoire, fin du programme.");
      fclose(file);
      return 0;
    }
  }
  fclose(file);
  return current_line;
}

void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)
{
  Pcap_loop_arg * pcap_args = (Pcap_loop_arg*) args;
  ETHER_Frame custom_frame;
  populate_packet_ds(header, packet, &custom_frame);
  rule_matcher(pcap_args->rules_ds, pcap_args->rules_ds_size, &custom_frame);
}

int main(int argc, char *argv[]) 
{
  // Lecture du nombre de règles
  if(argc != 2)
  {
    printf("usage ids <rule_file>\n");
    exit(1);
  }


  // Lecture des règles et populate rule_ds
  FILE * fptr;
  Rule * rules_ds = (Rule*) malloc(sizeof(Rule));
  printf("%s", rules_ds[0].protocol);
  fptr = fopen(argv[1], "r");
  if(fptr == NULL){
    printf("Erreur lors de l'ouverture du fichier\n");
    exit(1);
  }
  int nb_rule = read_rules(fptr, &rules_ds);
  if(nb_rule == 0)
  {
    printf("Aucune règle détectée, fin du programme.\n");
    free(rules_ds);
    exit(1);
  }

  // Test de rule_ds
  for(int i=0; i < nb_rule; i++)
  {
    printf("Action: %s\n", rules_ds[i].action);
    printf("Protocol: %s\n", rules_ds[i].protocol);
    printf("source address: %s\n", rules_ds[i].source_ad);
    printf("Source port: %s\n", rules_ds[i].source_po);
    printf("Direction: %s\n", rules_ds[i].direction);
    printf("Destination Adress: %s\n", rules_ds[i].destination_ad);
    printf("Destination Port: %s\n", rules_ds[i].destination_po);
    printf("Option key: %s\n", rules_ds[i].options[0].key);
    printf("Option Value: %s\n", rules_ds[i].options[0].value);
  }

  // Désignation du device + de l'handle pcap
  char *device = "eth0";
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  // Option de pcap
  handle = pcap_create(device,error_buffer);
  pcap_set_timeout(handle,10);
  pcap_activate(handle);
  int total_packet_count = 100;

  Pcap_loop_arg pcap_args;
  pcap_args.rules_ds = rules_ds;
  pcap_args.rules_ds_size = nb_rule;
  pcap_loop(handle, total_packet_count, my_packet_handler, (unsigned char *) &pcap_args);
  free(rules_ds);

  return 0;
}
