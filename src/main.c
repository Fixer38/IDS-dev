#include "populate.h"

struct ids_rule
{
  char * action;
  char * protocol;
  char source_ad[IP_ADDR_LEN_STR];
  int source_po;
  char direction;
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
  int current_line = 0;
  char line[100];
  while(current_line < count)
  {
    char * rule = strtok(line, " ");
    rules_ds[0].action = &rule[0];
    rules_ds[0].protocol = &rule[1];
    strcpy(rules_ds[0].source_ad, &rule[2]);
    rules_ds[0].source_po = rule[3];
    rules_ds[0].direction = rule[4];
    strcpy(rules_ds[0].destination_ad, &rule[5]);
    rules_ds[0].destination_po = rule[6];
    current_line++;
  }
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
  ETHER_Frame custom_frame;
  populate_packet_ds(header, packet, &custom_frame);
}

int main(int argc, char *argv[]) 
{
        // Lecture du nombre de règles
        FILE *fptr;
        fptr = fopen(argv[1], "r");
        int nb_line = count_line_in_file(fptr);
        printf("Nombre de règles dans le fichier: %d\n", nb_line);

        // Lecture des règles et populate rule_ds
        Rule rule_ds[nb_line];
        fptr = fopen(argv[1], "r");
        read_rules(fptr, rule_ds, nb_line);

        // Désignation du device + de l'handle pcap
        char *device = "wlp5s0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        // Option de pcap
        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
        int total_packet_count = 10;

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;
}
