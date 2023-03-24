#include "cJSON.h"
#include "cJSON.c"

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

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data
int tcp_sockfd;

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t tcp4_checksum(struct ip, struct tcphdr);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

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
void close_tcp_connection()
{
  close(tcp_sockfd);
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
    printf("bind failed\n");
    exit(EXIT_FAILURE);
  }

  // calculate size of data
  int total_data_len = config->udp_packets * (config->udp_payload_size);
  /*
  //allocate memory for data
  uint8_t *total_data = allocate_ustrmem(total_data_len);

  //set the packet ids for each payload
  uint8_t *ptr = total_data;
  for(uint16_t i = 0; i < config->udp_packets; i++){
    ptr = total_data + (i * config->udp_payload_size); //ptr points to the next payload section in the buffer
    *ptr++ = (uint8_t)(i >> 8); //writes the higher order byte
    *ptr = (uint8_t)(i & 0xff); //writes the lower order byte
  }
  */
  char total_data[config->udp_payload_size];
  if(entropy_flag==0){
    printf("Sending low entropy packet train");
    memset(total_data, 0, config->udp_payload_size);
  }
  else{
    printf("Sending low entropy packet train");
    FILE* fp;
    fp = fopen("highEntropyData", "r");
    memset(total_data, 0, config->udp_payload_size);
    fread(total_data,config->udp_payload_size,1,fp);
    fclose(fp);
  }
  // send to server
  //uint8_t *send_ptr = total_data;
  for (uint16_t i = 0; i < config->udp_packets; i++)
  {
    unsigned int temp = i;
    unsigned char lsb = (unsigned)(temp >> 8) & 0xff;
    unsigned char msb = (unsigned)temp & 0xff;
    total_data[0] = lsb; // set the first index to lower bit
    total_data[1] = msb; // set the second index to upper bit
    usleep(200);

    send_ptr = total_data + (i * config->udp_payload_size); // send_ptr points to the next payload section in the buffer
    if ((sendto(udp_sockfd, (char *)total_data, sizeof(total_data), MSG_CONFIRM, (const struct sockaddr *)&addr, sizeof(addr))) < 0)
    {
      printf("sendto failed for index: %u\n", i);
    }
    if(i%1000==0){
      printf("Sent %d udp packets\n",i);
    }
  }

  close(udp_sockfd);
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
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons(60);

  // Head Syn Destination port number (16 bits)
  tcphdr.th_dport = htons(config->destination_port_tcp_head_syn);

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

  // Send ethernet frame to socket.
  if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
  {
    perror("sendto() failed");
    exit(EXIT_FAILURE);
  }

  // Close socket descriptor.
  close(sd);

  send_udp_packet_train(entropy_flag);

  struct ip iphdr_2; //create second ip packet header

  //copy data from first ip header, overwrite necessary information
  memcpy(&iphdr_2, &iphdr, sizeof(struct ip));

  //calculate checksum for ip header
  iphdr_2.ip_sum = checksum((uint16_t *)&iphdr_2, IP4_HDRLEN);;

  //create second tcp header copied from the first one
  //overwrite relevant information
  struct tcphdr tcphdr_2;
  memcpy(&tcphdr_2, &tcphdr, sizeof(struct tcphdr));

  tcphdr_2.th_dport = htons(atoi(config->destination_port_tcp_tail_syn)); //set tail syn port

  tcphdr_2.th_seq = htonl(1); //sequence # is 1 because second packet

  //calculate tcp checksum
  tcphdr_2.th_sum = tcp4_checksum(iphdr_2, tcphdr_2);

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
  memcpy(ether_frame + ETH_HDRLEN, &iphdr_2, IP4_HDRLEN * sizeof(uint8_t));

  // TCP header
  memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr_2, TCP_HDRLEN * sizeof(uint8_t));

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
  /*Get config file path from arg*/
  char *config_path = args[1];

  /*Read config file and get cJSON object*/
  cJSON *json = read_config(config_path);

  /*Get config values into struct*/
  get_config_struct(json);

  /*Get config file in a string format*/
  char *json_str = cJSON_Print(json);

  send_packets(0);
  printf("Sleep for %d seconds", config->inter_measurement_time);
  sleep(config->inter_measurement_time);
  send_packets(1);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
uint16_t
checksum(uint16_t *addr, int len)
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
char *
allocate_strmem(int len)
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
uint8_t *
allocate_ustrmem(int len)
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