#include "cJSON.h"
#include "cJSON.c"
#include "packetHeaders.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD          // Use BSD format of tcp header
#include <netinet/tcp.h>     // struct tcphdr
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <linux/if.h>        // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <errno.h> // errno, perror()
#include <pcap.h>
#include <time.h>
#include <signal.h>

// global variables
clock_t low_start, low_end, high_start, high_end;
pcap_t *pcap_handle; /* packet capture handle */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14 // Ethernet header size

/* Packet sniffer pseudo-Ethernet header */

struct sniff_ethernet
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* Packet sniffer pseudo-IP header */
struct sniff_ip
{
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* Packet sniffer pseudo-TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

// handles timeout in receiving packets
// and ends packet sniffing loop
int break_loop = 0;
void stop_packet_capture(int sig)
{
  //pcap_breakloop(pcap_handle);
  break_loop=1;
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/* Ref : https://www.devdungeon.com/content/using-libpcap-c#pcap-loop*/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // static int count = 1;
  //   /* declare pointers to packet headers */
  // const struct ether_header *ethernet;  /* The ethernet header [1] */
  // const u_char *ip;              /* The IP header */
  // const u_char *tcp;            /* The TCP header */

  // int size_ip;
  // int size_tcp;

  // count++;

  // /* define ethernet header */
  // ethernet = (struct sniff_ethernet*)(packet);

  // /* define/compute ip header offset */
  // ip = (packet + SIZE_ETHERNET);
  // size_ip = ((*ip) & 0x0F);
  // if (size_ip < 20) {
  //   printf("   * Invalid IP header length: %u bytes\n", size_ip);
  //   return;
  // }

  // u_char protocol = *(ip + 9);
  //   if (protocol != IPPROTO_TCP) {
  //       printf("Not a TCP packet. Skipping...\n\n");
  //       return;
  //   }

  // /* define/compute tcp header offset */
  // tcp = (packet + SIZE_ETHERNET + size_ip);
  // size_tcp = ((*(tcp + 12)) & 0xF0) >> 4;
  // size_tcp = size_tcp * 4;
  // if (size_tcp < 20) {
  //   printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
  //   return;
  // }
  // printf("TCP header length in bytes: %d\n", size_tcp);
  // // int src_port = ntohs(tcp->th_sport);
  // // int dst_port = ntohs(tcp->th_dport);

  // if(count == 2){
  //   low_start = clock();
  //   printf("%ld",low_start);
  // }
  // else if(count == 3){
  //   low_end = clock();
  //   printf("%ld",low_end);
  // }
  // else if(count == 4){
  //   high_start = clock();
  //   printf("%ld",high_start);
  // }
  // else if(count == 5){
  //   high_end = clock();
  //   printf("%ld",high_end);
  // }

  // return;
  /* declare pointers to packet headers */
  static int count = 1;
  const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
  const struct sniff_ip *ip;             /* The IP header */
  const struct sniff_tcp *tcp;           /* The TCP header */

  int size_ip;
  int size_tcp;

  count++;

  /* define ethernet header */
  ethernet = (struct sniff_ethernet *)(packet);

  /* define/compute ip header offset */
  ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20)
  {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  printf("IP header received\n");

  /* define/compute tcp header offset */
  tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp) * 4;
  if (size_tcp < 20)
  {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
  printf("TCP header received\n");

  int src_port = ntohs(tcp->th_sport);
  int dst_port = ntohs(tcp->th_dport);
  printf("%d || %d || %d ",count, src_port, dst_port);
  if (count == 2 && src_port == 7777 && dst_port == 4444)
  {
    low_start = clock();
    printf("%ld", low_start);
  }
  else if (count == 3 && src_port == 9999 && dst_port == 4444)
  {
    low_end = clock();
    printf("%ld", low_end);
  }
  else if (count == 4 && src_port == 7777 && dst_port == 4444)
  {
    high_start = clock();
    printf("%ld", high_start);
  }
  else if (count == 5 && src_port == 9999 && dst_port == 4444)
  {
    high_end = clock();
    printf("%ld", high_end);
  }

  return;
}
// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
uint16_t checksum(uint16_t *addr, int len)
{

  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1)
  {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0)
  {
    sum += *(uint8_t *)addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16)
  {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr)
{

  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0]; // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
  ptr += sizeof(iphdr.ip_src.s_addr);
  chksumlen += sizeof(iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
  ptr += sizeof(iphdr.ip_dst.s_addr);
  chksumlen += sizeof(iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0;
  ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
  ptr += sizeof(iphdr.ip_p);
  chksumlen += sizeof(iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons(sizeof(tcphdr));
  memcpy(ptr, &svalue, sizeof(svalue));
  ptr += sizeof(svalue);
  chksumlen += sizeof(svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
  ptr += sizeof(tcphdr.th_sport);
  chksumlen += sizeof(tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
  ptr += sizeof(tcphdr.th_dport);
  chksumlen += sizeof(tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
  ptr += sizeof(tcphdr.th_seq);
  chksumlen += sizeof(tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
  ptr += sizeof(tcphdr.th_ack);
  chksumlen += sizeof(tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy(ptr, &cvalue, sizeof(cvalue));
  ptr += sizeof(cvalue);
  chksumlen += sizeof(cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
  ptr += sizeof(tcphdr.th_flags);
  chksumlen += sizeof(tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
  ptr += sizeof(tcphdr.th_win);
  chksumlen += sizeof(tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0;
  ptr++;
  *ptr = 0;
  ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
  ptr += sizeof(tcphdr.th_urp);
  chksumlen += sizeof(tcphdr.th_urp);

  return checksum((uint16_t *)buf, chksumlen);
}

// Allocate memory for an array of chars.
char *allocate_strmem(int len)
{

  void *tmp;

  if (len <= 0)
  {
    fprintf(stdout, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    printf("ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit(EXIT_FAILURE);
  }

  tmp = (char *)malloc(len * sizeof(char));
  if (tmp != NULL)
  {
    memset(tmp, 0, len * sizeof(char));
    return (tmp);
  }
  else
  {
    fprintf(stdout, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    printf("ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit(EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem(int len)
{

  void *tmp;

  if (len <= 0)
  {
    fprintf(stdout, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    printf("ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit(EXIT_FAILURE);
  }

  tmp = (uint8_t *)malloc(len * sizeof(uint8_t));
  if (tmp != NULL)
  {
    memset(tmp, 0, len * sizeof(uint8_t));
    return (tmp);
  }
  else
  {
    fprintf(stdout, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    printf("ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit(EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *allocate_intmem(int len)
{

  void *tmp;

  if (len <= 0)
  {
    fprintf(stdout, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    printf("ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit(EXIT_FAILURE);
  }

  tmp = (int *)malloc(len * sizeof(int));
  if (tmp != NULL)
  {
    memset(tmp, 0, len * sizeof(int));
    return (tmp);
  }
  else
  {
    fprintf(stdout, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    printf("ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit(EXIT_FAILURE);
  }
}

struct config
{
  char server_ip[50];
  int source_port_udp;
  int destination_port_udp;
  char destination_port_tcp_head_syn[50];
  char destination_port_tcp_tail_syn[50];
  int tcp_port;
  int udp_payload_size;
  int inter_measurement_time;
  int udp_packets;
  int time_to_live;
};
struct config *config;
struct cJSON *read_config(char *path)
{
  FILE *fp;
  char buffer[1024];

  /* Opening file in reading mode */
  fp = fopen(path, "r");
  fread(buffer, 1024, 1, fp);

  /* Parse json file */
  cJSON *json = cJSON_Parse(buffer);
  fclose(fp);
  return json;
}

void get_config_struct(cJSON *json)
{
  const cJSON *server_ip = NULL;
  const cJSON *src_port_udp = NULL;
  const cJSON *dst_port_udp = NULL;
  const cJSON *dst_port_tcp_head_syn = NULL;
  const cJSON *dst_port_tcp_tail_syn = NULL;
  const cJSON *tcp_port = NULL;
  const cJSON *udp_payload_size = NULL;
  const cJSON *inter_measurement_time = NULL;
  const cJSON *udp_packets = NULL;
  const cJSON *time_to_live = NULL;

  /* Parse config fields */
  server_ip = cJSON_GetObjectItemCaseSensitive(json, "server_ip");
  src_port_udp = cJSON_GetObjectItemCaseSensitive(json, "source_port_udp");
  dst_port_udp = cJSON_GetObjectItemCaseSensitive(json, "destination_port_udp");
  dst_port_tcp_head_syn = cJSON_GetObjectItemCaseSensitive(json, "destination_port_tcp_head_syn");
  dst_port_tcp_tail_syn = cJSON_GetObjectItemCaseSensitive(json, "destination_port_tcp_tail_syn");
  tcp_port = cJSON_GetObjectItemCaseSensitive(json, "tcp_port");
  udp_payload_size = cJSON_GetObjectItemCaseSensitive(json, "udp_payload_size");
  inter_measurement_time = cJSON_GetObjectItemCaseSensitive(json, "inter_measurement_time");
  udp_packets = cJSON_GetObjectItemCaseSensitive(json, "udp_packets");
  time_to_live = cJSON_GetObjectItemCaseSensitive(json, "time_to_live");

  /* Create config struct */
  config = malloc(sizeof *config);
  strcpy(config->server_ip, server_ip->valuestring);
  config->source_port_udp = src_port_udp->valueint;
  config->destination_port_udp = dst_port_udp->valueint;
  strcpy(config->destination_port_tcp_head_syn, dst_port_tcp_head_syn->valuestring);
  strcpy(config->destination_port_tcp_tail_syn, dst_port_tcp_tail_syn->valuestring);
  config->tcp_port = tcp_port->valueint;
  config->udp_payload_size = udp_payload_size->valueint;
  config->inter_measurement_time = inter_measurement_time->valueint;
  config->udp_packets = udp_packets->valueint;
  config->time_to_live = time_to_live->valueint;
}

void send_udp_packet_train(int entropy_flag)
{

  // create new sockaddr_in for udp
  struct sockaddr_in addr, srcaddr;
  int udp_sockfd;

  if ((udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("Error creating socket for UDP");
    exit(EXIT_FAILURE);
  }

  // set up socket structs
  memset(&addr, 0, sizeof(addr));                      // initialize memory to 0
  addr.sin_family = AF_INET;                           // set sin family
  inet_aton(config->server_ip, &addr.sin_addr);        // set source adddress
  addr.sin_port = htons(config->destination_port_udp); // set the destination port

  memset(&srcaddr, 0, sizeof(srcaddr));              // initialize memoryto 0
  srcaddr.sin_family = AF_INET;                      // set sin family
  srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);       // set home source address
  srcaddr.sin_port = htons(config->source_port_udp); // set the source port

  // set the don't fragment bit
  int value = IP_PMTUDISC_DO;
  if (setsockopt(udp_sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value)) < 0)
  {
    printf("unable to set DONT_FRAGMENT bit.\n");
    exit(EXIT_FAILURE);
  }

  // set the udp ttl from config file
  if (setsockopt(udp_sockfd, IPPROTO_IP, IP_TTL, &config->time_to_live, sizeof(config->time_to_live)) < 0)
  {
    printf("unable to set packet TTL to %u\n", config->time_to_live);
    exit(EXIT_FAILURE);
  }

  // bind socket to port
  if (bind(udp_sockfd, (struct sockaddr *)&srcaddr, sizeof(srcaddr)) < 0)
  {
    printf("bind failed for udp socket\n");
    exit(EXIT_FAILURE);
  }

  char buffer[config->udp_payload_size];
  if (entropy_flag == 0)
  {
    printf("Sending low entropy packet train\n");
    memset(buffer, 0, config->udp_payload_size);
  }
  else
  {
    printf("Sending high entropy packet train\n");
    FILE *fp;
    fp = fopen("highEntropyData", "r");
    memset(buffer, 0, config->udp_payload_size);
    fread(buffer, config->udp_payload_size, 1, fp);
    fclose(fp);
  }
  // send to server
  uint16_t i = 0;
  for (i = 0; i < config->udp_packets; i++)
  {
    unsigned int temp = i;
    unsigned char lsb = (unsigned)(temp >> 8) & 0xff;
    unsigned char msb = (unsigned)temp & 0xff;
    buffer[0] = lsb; // set the first index to lower bit
    buffer[1] = msb; // set the second index to upper bit
    usleep(200);

    if ((sendto(udp_sockfd, (char *)buffer, sizeof(buffer), MSG_CONFIRM, (const struct sockaddr *)&addr, sizeof(addr))) < 0)
    {
      printf("sendto failed for index: %u\n", i);
    }
  }
  printf("Sent %d udp packets\n", i);
  close(udp_sockfd);
}
/* Ref : https://www.devdungeon.com/content/using-libpcap-c#pcap-loop*/
void capture_packets()
{
  char *interface;
  interface = allocate_strmem(40);

  // Interface to receive packet through.
  strcpy(interface, "enp0s3");
}
int send_packets(int entropy_flag)
{
  int i, status, frame_length, sd, bytes, *ip_flags, *tcp_flags;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct tcphdr tcphdr;
  uint8_t *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;
  static int process_count = 0;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem(6);
  dst_mac = allocate_ustrmem(6);
  ether_frame = allocate_ustrmem(IP_MAXPACKET);
  interface = allocate_strmem(40);
  target = allocate_strmem(40);
  src_ip = allocate_strmem(INET_ADDRSTRLEN);
  dst_ip = allocate_strmem(INET_ADDRSTRLEN);
  ip_flags = allocate_intmem(4);
  tcp_flags = allocate_intmem(8);

  // Interface to send packet through.
  strcpy(interface, "enp0s3");
  
  // // set up packet sniffing
  // char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer for pcap */

  // // filtering for returning tcp packets from server with RST bit set
  // char filter_exp[] = "(tcp port (4444 or 7777 or 9999)) and (tcp[tcpflags] & (tcp-rst) == (tcp-rst))"; /* filter expression [3] */
  // struct bpf_program fp;                                                                                /* compiled filter program (expression) */
  // bpf_u_int32 mask;                                                                                     /* subnet mask */
  // bpf_u_int32 net;                                                                                      /* ip */
  // int num_packets = 4;                                                                                  /* number of packets to capture */

  // /* get network number and mask associated with capture device */
  // if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
  // {
  //   fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
  //   net = 0;
  //   mask = 0;
  // }

  // /* open capture device */
  // pcap_handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
  // if (pcap_handle == NULL)
  // {
  //   fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
  //   exit(EXIT_FAILURE);
  // }

  // /* make sure we're capturing on an Ethernet device */
  // if (pcap_datalink(pcap_handle) != DLT_EN10MB)
  // {
  //   fprintf(stderr, "%s is not an Ethernet\n", interface);
  //   exit(EXIT_FAILURE);
  // }

  // /* compile the filter expression */
  // if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1)
  // {
  //   fprintf(stderr, "Couldn't parse filter %s: %s\n",
  //           filter_exp, pcap_geterr(pcap_handle));
  //   exit(EXIT_FAILURE);
  // }

  // /* apply the compiled filter */
  // if (pcap_setfilter(pcap_handle, &fp) == -1)
  // {
  //   fprintf(stderr, "Couldn't install filter %s: %s\n",
  //           filter_exp, pcap_geterr(pcap_handle));
  //   exit(EXIT_FAILURE);
  // }
  
  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    perror("socket() failed to get socket descriptor for using ioctl() ");
    exit(EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
  if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
  {
    perror("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close(sd);

  // Copy source MAC address.
  memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

  // Report source MAC address to stdout.
  printf("MAC address for interface %s is ", interface);
  for (i = 0; i < 5; i++)
  {
    printf("%02x:", src_mac[i]);
  }
  printf("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset(&device, 0, sizeof(device));
  if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
  {
    perror("if_nametoindex() failed to obtain interface index ");
    exit(EXIT_FAILURE);
  }
  printf("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: you need to fill these out
  dst_mac[0] = 0x08;
  dst_mac[1] = 0x00;
  dst_mac[2] = 0x27;
  dst_mac[3] = 0x23;
  dst_mac[4] = 0xed;
  dst_mac[5] = 0x6e;

  // Source IPv4 address: you need to fill this out
  strcpy(src_ip, "10.0.0.136");

  // Destination URL or IPv4 address: you need to fill this out
  strcpy(target, config->server_ip);

  // Fill out hints for getaddrinfo().
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0)
  {
    fprintf(stdout, "getaddrinfo() failed for target: %s\n", gai_strerror(status));
    printf("getaddrinfo() failed for target: %s\n", gai_strerror(status));
    exit(EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *)res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL)
  {
    status = errno;
    fprintf(stdout, "inet_ntop() failed for target.\nError message: %s", strerror(status));
    printf("inet_ntop() failed for target.\nError message: %s", strerror(status));
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
  device.sll_halen = 6;
  /*
  if (process_count == 0)
  {
    process_count++;
    // Using a seperate child process to capture packets. Fork only when first tcp syn packet is sent.
    pid_t child_process = fork();
    if (child_process == 0)
    {
      printf("Child process forked\n");
      // Exit if packets not received in 60 seconds
      alarm(75);
      signal(SIGALRM, stop_packet_capture);
      printf("Alarm set for 60 sec\n");

      
      // capture incoming packets
      int result = pcap_loop(pcap_handle, num_packets, process_packet, NULL);
      printf("result %d\n", result);
      // free necessary elements
      pcap_freecode(&fp);
      pcap_close(pcap_handle);

      if (result == 0)
      { // if expected packets are received

        // calculate time elapsed in seconds
        double total_low = (((double)low_end) - ((double)low_start)) / ((double)CLOCKS_PER_SEC);
        double low_time = total_low * 1000; // convert seconds to milliseconds

        double total_high = (((double)high_end) - ((double)high_start)) / ((double)CLOCKS_PER_SEC);
        double high_time = total_high * 1000; // convert seconds to milliseconds

        printf("\nLow entropy time: %f ms\nHigh entropy time: %f ms\n", low_time, high_time);

        double difference = total_high - total_low;
        printf("Time difference was: %2f ms\n", difference);

        // Diagnisis
        if (difference <= 100)
        {
          printf("\nNo Network Compression detected.\n\n");
        }
        else
        {
          printf("\nNetwork Compression detected.\n\n");
        }
      }
      else if (result == -2)
      { // if timeout occurs before we get all the packets
        printf("Timeout Occurred.\n");
        printf("\nFailed to detect network compression due to insufficient information.\n\n");
      }
      else
      { // if any other error occurs
        printf("Pcap error occurred.\n");
      }

      // terminate child process
      exit(0);
    }
    
  }
*/
  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + TCP header
  iphdr.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons(0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1)
  {
    fprintf(stdout, "inet_pton() failed for source address.\nError message: %s", strerror(status));
    printf("inet_pton() failed for source address.\nError message: %s", strerror(status));
    exit(EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
  {
    fprintf(stdout, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
    printf("inet_pton() failed for destination address.\nError message: %s", strerror(status));
    exit(EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons(4444);

  // Head Syn Destination port number (16 bits)
  tcphdr.th_dport = htons(atoi(config->destination_port_tcp_head_syn));

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl(0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl(0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 1;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 0;

  // ACK flag (1 bit)
  tcp_flags[4] = 0;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i = 0; i < 8; i++)
  {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons(65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons(0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = tcp4_checksum(iphdr, tcphdr);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN;

  // Destination and Source MAC addresses
  memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
  memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IP / 256;
  ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + TCP header).

  // IPv4 header
  memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

  // TCP header
  memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

  // Submit request for a raw socket descriptor.
  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  if(process_count==0){
    process_count++;
    pid_t child_process = fork();
    if(child_process==0){
      printf("Child process created\n");
      
      char buffer[4096];
      bzero(buffer, 4096);
      int i =0;
      int rst_count = 0;
      while(break_loop==0){
        int n=0;
        if((n = recv(sd, (char *)buffer, sizeof(buffer),0))<0){
          printf("Error in recv");
        }
        if(i==0 & n>0){
          alarm(60);
          signal(SIGALRM, stop_packet_capture);
        }
        i++;
        // Extract Ethernet header, IP header, and TCP header
        struct ether_header *eth_header = (struct ether_header *)buffer;
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
        struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
        if (tcph->rst && tcph->th_ack) {
            rst_count++;
            printf("Received RST # = %d packet at %ld. src :%d dst: %d \n", rst_count, clock(), ntohs(tcph->source), ntohs(tcph->dest));
        }
        bzero(buffer, 4096);
        // } else {
        //     printf("Received unexpected packet.\n");
        // }
      }
      return EXIT_SUCCESS;
    }
 }
  

  // Send ethernet frame to socket.
  if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
  {
    perror("sendto() failed");
    exit(EXIT_FAILURE);
  }

  // Close socket descriptor.
  close(sd);

  send_udp_packet_train(entropy_flag);

  struct ip iphdr_2; // create second ip packet header

  // copy data from first ip header, overwrite necessary information
  memcpy(&iphdr_2, &iphdr_2, sizeof(struct ip));

  // // IPv4 header

  // // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  // iphdr_2.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

  // // Internet Protocol version (4 bits): IPv4
  // iphdr_2.ip_v = 4;

  // // Type of service (8 bits)
  // iphdr_2.ip_tos = 0;

  // // Total length of datagram (16 bits): IP header + TCP header
  // iphdr_2.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN);

  // // ID sequence number (16 bits): unused, since single datagram
  // iphdr_2.ip_id = htons(0);

  // // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // // Zero (1 bit)
  // ip_flags[0] = 0;

  // // Do not fragment flag (1 bit)
  // ip_flags[1] = 0;

  // // More fragments following flag (1 bit)
  // ip_flags[2] = 0;

  // // Fragmentation offset (13 bits)
  // ip_flags[3] = 0;

  // iphdr_2.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);

  // // Time-to-Live (8 bits): default to maximum value
  // iphdr_2.ip_ttl = 255;

  // // Transport layer protocol (8 bits): 6 for TCP
  // iphdr_2.ip_p = IPPROTO_TCP;

  // // Source IPv4 address (32 bits)
  // if ((status = inet_pton(AF_INET, src_ip, &(iphdr_2.ip_src))) != 1)
  // {
  //   fprintf(stdout, "inet_pton() failed for source address.\nError message: %s", strerror(status));
  //   printf("inet_pton() failed for source address.\nError message: %s", strerror(status));
  //   exit(EXIT_FAILURE);
  // }

  // // Destination IPv4 address (32 bits)
  // if ((status = inet_pton(AF_INET, dst_ip, &(iphdr_2.ip_dst))) != 1)
  // {
  //   fprintf(stdout, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
  //   printf("inet_pton() failed for destination address.\nError message: %s", strerror(status));
  //   exit(EXIT_FAILURE);
  // }

  // calculate checksum for ip header
  iphdr_2.ip_sum = checksum((uint16_t *)&iphdr_2, IP4_HDRLEN);

  // create second tcp header copied from the first one
  // overwrite relevant information
  struct tcphdr tcphdr_2;
  memcpy(&tcphdr_2, &tcphdr, sizeof(struct tcphdr));

  // // Source port number (16 bits)
  // tcphdr_2.th_sport = htons(4444);

  tcphdr_2.th_dport = htons(atoi(config->destination_port_tcp_tail_syn)); // set tail syn port

  tcphdr_2.th_seq = htonl(1); // sequence # is 1 because second packet

  // // Reserved (4 bits): should be 0
  // tcphdr_2.th_x2 = 0;

  // // Data offset (4 bits): size of TCP header in 32-bit words
  // tcphdr_2.th_off = TCP_HDRLEN / 4;

  // // Flags (8 bits)

  // // FIN flag (1 bit)
  // tcp_flags[0] = 0;

  // // SYN flag (1 bit): set to 1
  // tcp_flags[1] = 1;

  // // RST flag (1 bit)
  // tcp_flags[2] = 0;

  // // PSH flag (1 bit)
  // tcp_flags[3] = 0;

  // // ACK flag (1 bit)
  // tcp_flags[4] = 0;

  // // URG flag (1 bit)
  // tcp_flags[5] = 0;

  // // ECE flag (1 bit)
  // tcp_flags[6] = 0;

  // // CWR flag (1 bit)
  // tcp_flags[7] = 0;

  // tcphdr_2.th_flags = 0;
  // for (i = 0; i < 8; i++)
  // {
  //   tcphdr_2.th_flags += (tcp_flags[i] << i);
  // }

  // // Window size (16 bits)
  // tcphdr_2.th_win = htons(65535);

  // // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  // tcphdr_2.th_urp = htons(0);

  // calculate tcp checksum
  tcphdr_2.th_sum = tcp4_checksum(iphdr_2, tcphdr_2);

  // // Fill out ethernet frame header.

  // // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
  // frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN;

  // // Destination and Source MAC addresses
  // memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
  // memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

  // // Next is ethernet type code (ETH_P_IP for IPv4).
  // // http://www.iana.org/assignments/ethernet-numbers
  // ether_frame[12] = ETH_P_IP / 256;
  // ether_frame[13] = ETH_P_IP % 256;

  // // Next is ethernet frame data (IPv4 header + TCP header).

  // // IPv4 header
  // memcpy(ether_frame + ETH_HDRLEN, &iphdr_2, IP4_HDRLEN * sizeof(uint8_t));

  // // TCP header
  // memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr_2, TCP_HDRLEN * sizeof(uint8_t));

  // Submit request for a raw socket descriptor.
  if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
  {
    perror("socket() failed ");
    exit(EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
  {
    perror("sendto() failed");
    exit(EXIT_FAILURE);
  }

  // Close socket descriptor.
  close(sd);

  // Free allocated memory.
  free(src_mac);
  free(dst_mac);
  free(ether_frame);
  free(interface);
  free(target);
  free(src_ip);
  free(dst_ip);
  free(ip_flags);
  free(tcp_flags);

  return (EXIT_SUCCESS);
}
void main(int argc, char *args[])
{
  if (argc < 2)
  {
    printf("Insufficient arguments. Please provide config file.\n");
    return;
  }
  int main_pid = getpid();

  /*Get config file path from arg*/
  char *config_path = args[1];

  /*Read config file and get cJSON object*/
  cJSON *json = read_config(config_path);

  /*Get config values into struct*/
  get_config_struct(json);

  /*Get config file in a string format*/
  char *json_str = cJSON_Print(json);
  //capture_packets();
  
  // Low entropy data packet train
  send_packets(0);
  if(getpid()== main_pid){
    printf("Sleep for %d seconds\n", config->inter_measurement_time);
    
    sleep(config->inter_measurement_time);
    
    // High entropy data packet train
    send_packets(1);
  } else{
    printf("Terminating Program.\n");
  }
  // wait for the child process to complete before terminating the program
  wait(0);

  return;
}