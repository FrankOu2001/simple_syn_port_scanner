#include "sniffer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <pthread.h>

#define PORT 32654

int begin_port, end_port;
struct in_addr dest_ip;

int 
main(int argc, char *argv[]) {
  deal_args(argc, argv);
  srand(time(NULL));


  char datagram[DATAGRAM_SIZE];
  char source_ip[20];

  struct sockaddr_in dest;
  struct psd_header psh;
  struct tcphdr *tcph;
  pthread_t thread;
 
  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock < 0) {
    fprintf(stderr, "Failed to open a raw socket: %s\n", strerror(errno));
    exit(-1);
  }

  set_datagram(datagram, source_ip);

  const int yes = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) < 0) {
    fprintf(stderr, "Error setting IP_HDRINCL. Error Message: %s\n", strerror(errno));
    exit(-1);
  }

  const int count = end_port - begin_port + 1;
  if (pthread_create(&thread, NULL, receive_packet, (void *)&count) < 0) {
    fprintf(stderr, "Failed to create thread: %s\n", strerror(errno));
    exit(-1);
  }

  dest.sin_family = PF_INET;
  dest.sin_addr.s_addr = dest_ip.s_addr;
  size_t psd_len = sizeof(struct tcphdr) + sizeof(tcp_max_segment_option);
  // unsigned short psd_len = sizeof(struct tcphdr);
  size_t data_len = sizeof(struct iphdr) + sizeof(struct tcphdr) 
                    + sizeof(tcp_max_segment_option);
  tcph = (struct tcphdr*)(datagram + sizeof(struct ip));

  puts("开始发送数据");
  for (unsigned port = begin_port, cnt = 1; port <= end_port; ++port, ++cnt) {
    if (cnt % 1000 == 0) {
      sleep(1);
    }
    tcph->th_dport = htons(port);
    tcph->th_sum = 0;
    psh.s_addr = inet_addr(source_ip);
    psh.d_addr = dest.sin_addr.s_addr;
    psh.place_holder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.len = htons(psd_len);

    memcpy(&psh.tcp, (void *)tcph, psd_len);

    tcph->th_sum = csum((unsigned short *)&psh, sizeof(struct psd_header));

    if (sendto(sock, datagram, data_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
      fprintf(stderr, "Send packet on port %d error: %s\n", port, strerror(errno));
      exit(-1);
    }
  }
  close(sock);

  pthread_join(thread, NULL);

  return 0;
}

char*
get_default_dev(char *errbuf) {
  char local_ip[20];
  get_local_ip(local_ip);
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    return NULL;
  }

  for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
    for (pcap_addr_t *t = dev->addresses; t != NULL; t = t->next) {
      char *dev_ip = inet_ntoa(((struct sockaddr_in *)t->addr)->sin_addr);
      if (t->addr->sa_family == PF_INET && strcmp(local_ip, dev_ip) == 0) {
        return dev->name;
      }
    }
  }

  sprintf(errbuf, "No device's ip address is %s", local_ip);

  return NULL;
}

void *
receive_packet(void *count) {
  printf("There will send %d packet(s)\n", *(int*)count);
  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev;
  pcap_t *handle;
  struct bpf_program fp;
  bpf_u_int32 mask,
              net;

  char filter_exp[24];
  if (sprintf(filter_exp, "src host %s", inet_ntoa(dest_ip)) < 0) {
    fprintf(stderr, "Error get filter_exp: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  dev = get_default_dev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Failed to get defefault dev: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  time_t time = (end_port - begin_port + 999) / 1000 * 1000 + 2000;
  handle = pcap_open_live(dev, BUFSIZ, 1, time, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  pcap_dispatch(handle, *(int*)count, start_sniffer, NULL);

  pcap_freecode(&fp);
  pcap_close(handle);
  puts("Stop Receive.");

  return NULL;
}

void
start_sniffer(unsigned char *args, 
              const struct pcap_pkthdr *header, const u_char *packet) {

  const struct ip *iph = (struct ip*)(packet + 14);
  const struct tcphdr* tcph = (struct tcphdr*)(packet + 14 + sizeof(struct ip));


  if (tcph->th_flags & TH_SYN) {
    printf("From: %s, port: %d is open\n", inet_ntoa(iph->ip_src), ntohs(tcph->th_sport));
  }
}

void 
set_datagram(void *datagram, char *s_ip) {
  memset(datagram, 0, DATAGRAM_SIZE);
  char *d = (char *)datagram;

  int s_port = PORT;
  // IP Header
  struct ip *iph = (struct ip *)datagram;
  // TCP Header
  struct tcphdr *tcph = (struct tcphdr *)(d + sizeof(struct ip));
  // TCP Option
  tcp_max_segment_option *opt = 
    (tcp_max_segment_option*)(d + sizeof(struct ip) + sizeof(struct tcphdr));

  get_local_ip(s_ip);
  
  // set IP Header 
  iph->ip_hl  = 5;
  iph->ip_v   = 4;
  iph->ip_tos = 0;
  iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) 
                + sizeof(tcp_max_segment_option);

  // iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
  iph->ip_id  = htons(54321);
  iph->ip_off = 0; // 这个系统内核能搞定
  iph->ip_ttl = 64;
  iph->ip_p   = IPPROTO_TCP;
  iph->ip_sum = 0;
  iph->ip_src.s_addr = inet_addr(s_ip);
  iph->ip_dst.s_addr = dest_ip.s_addr;
  // caculate checksum
  iph->ip_sum = csum((unsigned short *)datagram, iph->ip_len / 2);

  // set TCP Header;
  tcph->th_sport = htons(s_port);
  tcph->th_dport = htons(80);
  tcph->th_seq   = htonl(123456789);
  tcph->th_ack   = 0;
  tcph->th_off   = (sizeof(struct tcphdr) + sizeof(tcp_max_segment_option)) / 4;
  // tcph->th_off   = (sizeof(struct tcphdr)) / 4;
  tcph->th_flags = TH_SYN;
  tcph->th_win   = htons(1024);
  tcph->th_sum   = 0;
  tcph->th_urp   = 0;

  opt->kind = 0x2;
  opt->len = 0x4;
  opt->val = 0xb405;
}

unsigned short 
csum(unsigned short * ptr, int size) {
  long  sum = 0;
  unsigned char oddbyte;
  short ret;

  while (size > 1) {
    sum += *ptr++;
    size -= 2;
  }
  if (size) {
    oddbyte = *(unsigned char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  ret = ~(short)sum;

  return ret;
}

char *
hostname_to_ip(char *hostname) {
  struct hostent *host;
  struct in_addr **addr_list;

  if ((host = gethostbyname(hostname)) == NULL) 
    goto end;

  addr_list = (struct in_addr **)host->h_addr_list;

  for (int i = 0; addr_list[i] != NULL; i++) {
    return inet_ntoa(*addr_list[i]);
  }

end:
  return NULL;
}

int 
get_local_ip(char *buffer) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);

  const char dns[] = "114.114.114.114";
  int dns_port = 53;

  struct sockaddr_in serv;
  memset(&serv, 0, sizeof(serv));
  serv.sin_family = PF_INET;
  serv.sin_addr.s_addr = inet_addr(dns);
  serv.sin_port = htons(dns_port);

  if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
    fprintf(stderr, "Failed to connect to %s: %s\n", dns, strerror(errno));
    return -1;
  }

  struct sockaddr_in name;
  socklen_t name_len = sizeof(name);

  if (getsockname(sock, (struct sockaddr *)&name, &name_len) < 0) {
    fprintf(stderr, "Failed to get sock's name\n");
    return -1;
  }
  
  const char *p = inet_ntop(PF_INET, &name.sin_addr, buffer, 100);
  printf("localhost's ip is %s\n", p);
  close(sock);
  return 1;
}

void 
deal_args(int argc, char **argv) {
  /*
   * 判断传入参数
   * check whether args are right or not
  */
  if (argc < 2) {
    printf("Usage: %s dest_host [begin_port end_port]\n"
           ,argv[0]);

    exit(2);
  }

  // get local ip
  char *target;
  target = argv[1];
  if (inet_addr(target) != -1) {
    dest_ip.s_addr = inet_addr(target);
    printf("target is: %s\n", target);
  } else {
    char *ip = hostname_to_ip(target);
    if (ip != NULL) {
      // printf("target %s resolved to %s\n", target, ip);
      printf("target is: %s(%s)\n", target, ip);
      dest_ip.s_addr = inet_addr(ip);
    }
    else {
      fprintf(stderr, "Can't resolve target: %s\n", target);
      exit(2);
    }
  }

  switch (argc) {
    case 2:
     
      begin_port = 0;
      end_port = 65535;
    break;

    case 3:
    case 4:
      if (!strcmp(argv[2], "0") || atoi(argv[2]) < 0 || atoi(argv[2]) > 65535) {
        fprintf(stderr, "Invalid port number\n");
        exit(2);
      }
      if (argc == 3) break;

      if (!strcmp(argv[3], "0") || atoi(argv[3]) < 0 || atoi(argv[3]) > 65535) {
        fprintf(stderr, "Invalid port number\n");
        exit(2);
      }
      
      int l = atoi(argv[2]), r = atoi(argv[3]);
      if (atoi(argv[2]) > atoi(argv[3])) {
        fprintf(stderr, "Invalid port range: [%d-%d]\n", l, r);
        exit(2);
      }
      else {
        begin_port = l;
        end_port = r;
      }
    break;
  }
}
