#include "populate.h"

struct rule_option
{
  char key[20];
  char value[50];
} typedef Rule_option;

struct ids_rule
{
  char action[6];
  char protocol[6];
  char source_ad[IP_ADDR_LEN_STR];
  char source_po[5];
  char direction[3];
  char destination_ad[IP_ADDR_LEN_STR];
  char destination_po[5];
  Rule_option options[2];
} typedef Rule;

struct pcap_loop_arg
{
  int rules_ds_size;
  Rule * rules_ds;
} typedef Pcap_loop_arg;

void rule_matcher(Rule *rules_ds, int rules_ds_size, ETHER_Frame *frame)
{
  for(int i = 0; i < rules_ds_size; i++)
  {
    if(strcmp(rules_ds[i].protocol, "http") == 0 && strstr(frame->data.data.data, "HTTP") != NULL)
    {
      printf("HTTP PACKET RECEIVED");
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
}

void read_rules(FILE * file, Rule *rules_ds, int count)
{
  int current_line = 0;
  char line[100];
  while(fgets(line, 100, file) != NULL)
  {
    parse_rule(line, rules_ds, current_line);
    current_line++;
  }
  fclose(file);
}

int count_line_in_file(FILE * file)
{
  char line[100];
  int nb_line = 0;
  if(file == NULL)
  {
    printf("Erreur lors de l'ouverture du fichier\n");
    fclose(file);
    return 0;
  }
  while(fgets(line, 100, file) != NULL)
  {
    nb_line++;
  }
  fclose(file);
  return nb_line;
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
  printf("%s", custom_frame.data.data.data);
  rule_matcher(pcap_args->rules_ds, pcap_args->rules_ds_size, &custom_frame);
}

int main(int argc, char *argv[]) 
{
        // Lecture du nombre de règles
        FILE *fptr;
        fptr = fopen(argv[1], "r");
        int nb_line = count_line_in_file(fptr);
        printf("Nombre de règles dans le fichier: %d\n", nb_line);

        // Lecture des règles et populate rule_ds
        Rule rules_ds[nb_line];
        fptr = fopen(argv[1], "r");
        read_rules(fptr, rules_ds, nb_line);

        // Test de rule_ds
        for(int i=0; i < nb_line; i++)
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
        char *device = "wlp5s0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        // Option de pcap
        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 100;

        Pcap_loop_arg pcap_args;
        pcap_args.rules_ds = rules_ds;
        pcap_args.rules_ds_size = nb_line;
        pcap_loop(handle, total_packet_count, my_packet_handler, (unsigned char *) &pcap_args);

        return 0;
}
