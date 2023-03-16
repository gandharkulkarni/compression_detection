#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "cJSON.h"
#include "cJSON.c"
#define SA struct sockaddr

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
void print_config()
{
    printf("\n{\nServer IP : %s\n", config->server_ip);
    printf("Source port UDP : %d\n", config->source_port_udp);
    printf("Destination port UDP : %d\n", config->destination_port_udp);
    printf("Destination port TCP Head SYN : %s\n", config->destination_port_tcp_head_syn);
    printf("Destination port TCP Tail SYN : %s\n", config->destination_port_tcp_tail_syn);
    printf("TCP Port : %d\n", config->tcp_port);
    printf("UDP Payload size : %d\n", config->udp_payload_size);
    printf("Inter measurement time : %d\n", config->inter_measurement_time);
    printf("UDP Packets : %d\n", config->udp_packets);
    printf("Time to live : %d\n}\n", config->time_to_live);
}
struct config *get_config_file(int connfd)
{
    char buff[4096];
    int n;
    bzero(buff, 4096);
    /* read the config from client and copy it in buffer */
    read(connfd, buff, sizeof(buff));
    char *output;
    output = &buff;

    /* Get cJSON object from received string */
    cJSON *json = cJSON_Parse(output);
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

    /*Parse config fields*/
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

    /*Create config struct*/
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
void get_config_file_from_client(int tcp_listen_port)
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;

    /* socket create */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    /* assign IP, PORT */
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(tcp_listen_port);

    /* Binding socket to given IP */
    if ((bind(sockfd, (SA *)&servaddr, sizeof(servaddr))) != 0)
    {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    /* Server listen */
    if ((listen(sockfd, 5)) != 0)
    {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);

    /* Accept the data packet from client */
    connfd = accept(sockfd, (SA *)&cli, &len);
    if (connfd < 0)
    {
        printf("server accept failed...\n");
        exit(0);
    }
    else
        printf("server accept the client...\n");

    /* Get config file from client */
    get_config_file(connfd);
    char *response = "Configuration received";
    write(connfd, response, sizeof(response) * strlen(response));
    close(sockfd);
}
void receive_packets_from_client()
{
    int sockfd;
    char buffer[1024];
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created\n");
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(config->destination_port_udp);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr,
             sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Bind successful\n");
    socklen_t len;
    int n;

    len = sizeof(cliaddr); // len is value/result
    printf("Receiving...\n");
    n = recvfrom(sockfd, (char *)buffer, 1024,
                 MSG_WAITALL, (struct sockaddr *)&cliaddr,
                 &len);
    buffer[n] = '\0';
    printf("Client : %s\n", buffer);
}
void main(int argc, char *args[])
{
    if (argc < 2)
    {
        printf("Insufficient arguments. Please provide config file.\n");
        return;
    }
    int tcp_listen_port = atol(args[1]);
    get_config_file_from_client(tcp_listen_port);
    //print_config();
    receive_packets_from_client();
}