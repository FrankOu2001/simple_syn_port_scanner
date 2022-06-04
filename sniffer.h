#define DATAGRAM_SIZE 4096

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __APPLE__
#define iphdr ip
#endif

unsigned short csum(unsigned short *, int);
char *hostname_to_ip(char *);
char* get_default_dev(char *);
int get_local_ip(char *);
void set_datagram(void *, char *);
void *receive_packet(void*);
void deal_args(int argc, char **argv);
void start_sniffer(unsigned char*, const struct pcap_pkthdr *, const u_char *);
 
typedef struct max_segment_options {
  unsigned char   kind;
  unsigned char   len;
  unsigned short  val;
} tcp_max_segment_option;

struct psd_header {
  unsigned        s_addr;
  unsigned        d_addr;
  unsigned char   place_holder;
  unsigned char   protocol; 
  unsigned short  len;

  struct tcphdr tcp;
  struct max_segment_options opt;
};
