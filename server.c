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
#include <time.h>
#include <signal.h>
#define SA struct sockaddr
int break_loop = 0;
int tcp_sockfd, udp_sockfd;
struct config
{
    char server_ip[50];
    int source_port_udp;
    int destination_port_udp;
    int destination_port_tcp_head_syn;
    int destination_port_tcp_tail_syn;
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
    printf("Destination port TCP Head SYN : %d\n", config->destination_port_tcp_head_syn);
    printf("Destination port TCP Tail SYN : %d\n", config->destination_port_tcp_tail_syn);
    printf("TCP Port : %d\n", config->tcp_port);
    printf("UDP Payload size : %d\n", config->udp_payload_size);
    printf("Inter measurement time : %d\n", config->inter_measurement_time);
    printf("UDP Packets : %d\n", config->udp_packets);
    printf("Time to live : %d\n}\n", config->time_to_live);
}

void break_deadlock(int sig)
{
  break_loop = 1;
}
void close_tcp_connection(){
    close(tcp_sockfd);
}
void initialize_config(int connfd)
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
    config->destination_port_tcp_head_syn = dst_port_tcp_head_syn->valueint;
    config->destination_port_tcp_tail_syn = dst_port_tcp_tail_syn->valueint;
    config->tcp_port = tcp_port->valueint;
    if (udp_payload_size->valueint == 0)
    {
        config->udp_payload_size = 1000;
    }
    else
    {
        config->udp_payload_size = udp_payload_size->valueint;
    }
    if (inter_measurement_time->valueint == 0)
    {
        config->inter_measurement_time = 15;
    }
    else
    {
        config->inter_measurement_time = inter_measurement_time->valueint;
    }
    if (udp_packets->valueint == 0)
    {
        config->udp_packets = 6000;
    }
    else
    {
        config->udp_packets = udp_packets->valueint;
    }
    if (time_to_live->valueint == 0)
    {
        config->time_to_live = 255;
    }
    else
    {
        config->time_to_live = time_to_live->valueint;
    }
}
float receive_packets_from_client()
{
    int sockfd;
    unsigned char buffer[config->udp_payload_size];
    struct sockaddr_in servaddr, cliaddr;
    memset(buffer, 0, config->udp_payload_size);

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("Socket created\n");
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(config->destination_port_udp);

    cliaddr.sin_family = AF_INET;
    cliaddr.sin_port = htons(config->source_port_udp);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Bind successful\n");
    socklen_t len;
    int n;

    len = sizeof(cliaddr); // len is value/result
    clock_t low_entr_start_time, low_entr_end_time, high_entr_start_time, high_entr_end_time;
	double total_time, low_entr_time, high_entr_time = 0;
    printf("Receiving...\n");
    int i=0;
    while(i < config->udp_packets && break_loop == 0)
    {
        n = recvfrom(sockfd, (char *)buffer, sizeof(buffer),MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        int id = (buffer[0] << 8  | buffer[1]);
        //printf("%d\t", id);
        if (i == 0 && n > 0)
        {
            low_entr_start_time = clock();
            /* break the loop if not all packets are received after 10 seconds */
            //alarm(10);
            //signal(SIGALRM, break_deadlock);
        }
        if(i>0 && n>0){
            low_entr_end_time = clock();
        }
        i++;
        //printf("Received low entropy packets. Count : %d \n", i);
    }
    printf("Received %d packets.\n", i);
    //calculate time elapsed in seconds
	total_time = (((double)low_entr_end_time) - ((double)low_entr_start_time)) / ((double)CLOCKS_PER_SEC);
	low_entr_time = total_time*1000; //convert seconds to milliseconds
    printf("Low entropy packet train : Size: %d, time :%f\n", i, low_entr_time);
    

    printf("Receiving...\n");
    i=0;
    break_loop=0;
    while(i < config->udp_packets && break_loop == 0)
    {
        n = recvfrom(sockfd, (char *)buffer, sizeof(buffer), MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        int id = (buffer[0] << 8  | buffer[1]);
        //printf("%d\t", id);
        if (i == 0 && n > 0)
        {
            high_entr_start_time = clock();
            /* break the loop if not all packets are received after 10 seconds */
            //alarm(10); 
            //signal(SIGALRM, break_deadlock);
        }
        if(i>0 && n>0){
            high_entr_end_time = clock();
        }
        i++;
        //printf("%ld",high_entr_end_time);
        //printf("Received high entropy packets. Count : %d \n", i);
    }
    printf("Received %d packets.\n", i);
    total_time = (((double)high_entr_end_time) - ((double)high_entr_start_time)) / ((double)CLOCKS_PER_SEC);
	high_entr_time = total_time*1000; //convert seconds to milliseconds
    printf("High entropy packet train : Size: %d, time :%f\n", i, high_entr_time);
    printf("Difference: %f\n", high_entr_time-low_entr_time);
    return high_entr_time-low_entr_time;
}
int listen_on_port(int tcp_listen_port)
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
    int optval = 1;
    if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0)
    {
        perror("couldnt reuse address");
        exit(EXIT_FAILURE);
    }

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
    
    tcp_sockfd = sockfd;
    return connfd;
    /* Get config file from client */
    // get_config_file(connfd);
    // char *response = "Configuration received";
    // write(connfd, response, sizeof(response) * strlen(response));
    // close(sockfd);
}
void main(int argc, char *args[])
{
    if (argc < 2)
    {
        printf("Insufficient arguments. Please provide config file.\n");
        return;
    }
    int tcp_listen_port = atol(args[1]);
    int connfd = listen_on_port(tcp_listen_port);

    initialize_config(connfd);
    char *response = "Configuration received";
    write(connfd, response, sizeof(response) * strlen(response));
    close_tcp_connection();

    float threshold = 100;
    float difference = receive_packets_from_client();
    if(difference>threshold){
        response = "Compression detected";
    }
    else{
        response = "No compression detected";
    }
    printf("%s\n",response);
    connfd = listen_on_port(tcp_listen_port);
    write(connfd, response, sizeof(response) * strlen(response));
    close_tcp_connection();
}