#include"cJSON.h"
#include"cJSON.c"
#include<stdio.h>
#include<stdlib.h>
#include<netdb.h>
#include<netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>
#define SA struct sockaddr
struct config{
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
struct config* read_config_file(char* path){
    FILE* fp;
    char buffer[1024];
    /* Opening file in reading mode */
    fp = fopen(path, "r");
    fread(buffer,1024,1,fp);
    /* Parse json file */
    cJSON* json = cJSON_Parse(buffer);
    fclose(fp);

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
    server_ip =  cJSON_GetObjectItemCaseSensitive(json, "server_ip");
    src_port_udp =  cJSON_GetObjectItemCaseSensitive(json, "source_port_udp");
    dst_port_udp =  cJSON_GetObjectItemCaseSensitive(json, "destination_port_udp");
    dst_port_tcp_head_syn =  cJSON_GetObjectItemCaseSensitive(json, "destination_port_tcp_head_syn");
    dst_port_tcp_tail_syn =  cJSON_GetObjectItemCaseSensitive(json, "destination_port_tcp_tail_syn");
    tcp_port =  cJSON_GetObjectItemCaseSensitive(json, "tcp_port");
    udp_payload_size =  cJSON_GetObjectItemCaseSensitive(json, "udp_payload_size");
    inter_measurement_time = cJSON_GetObjectItemCaseSensitive(json,"inter_measurement_time");
    udp_packets = cJSON_GetObjectItemCaseSensitive(json, "udp_packets");
    time_to_live = cJSON_GetObjectItemCaseSensitive(json, "time_to_live");

    /*Create config struct*/
    struct config *config = malloc(sizeof *config);
    strcpy(config->server_ip,server_ip->valuestring);
    config->source_port_udp = src_port_udp->valueint;
    config->destination_port_udp = dst_port_udp->valueint;
    strcpy(config->destination_port_tcp_head_syn, dst_port_tcp_head_syn->valuestring);
    strcpy(config->destination_port_tcp_tail_syn, dst_port_tcp_tail_syn->valuestring);
    config->tcp_port = tcp_port->valueint;
    config->udp_payload_size = udp_payload_size->valueint;
    config->inter_measurement_time = inter_measurement_time->valueint;
    config->udp_packets = udp_packets->valueint;
    config->time_to_live = time_to_live->valueint;

    return config;
}
void main(int argc, char *args[]){
    if(argc<2){
        printf("Insufficient arguments. Please provide config file.\n");
        return;
    }
    /*
    char* config_path = args[1];
    struct config *config = read_config_file(config_path);
    printf("%s\n", config->server_ip);
    printf("%d\n", config->source_port_udp);
    printf("%d\n", config->destination_port_udp);
    printf("%s\n", config->destination_port_tcp_head_syn);
    printf("%s\n", config->destination_port_tcp_tail_syn);
    printf("%d\n", config->tcp_port);
    printf("%d\n", config->udp_payload_size);
    printf("%d\n", config->inter_measurement_time);
    printf("%d\n", config->udp_packets);
    printf("%d\n", config->time_to_live);
    */
   int sockfd, connfd;
   struct sockaddr_in servaddr, cli;
 
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("10.0.0.251");
    servaddr.sin_port = htons(8080);
 
    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))
        != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
 
    // function for chat
    sendMsg(sockfd);
    close(sockfd);
}

void sendMsg(int socketfd){
    char buffer[80];
    int n;
    for(;;){
        bzero(buffer,sizeof(buffer));
        printf("Enter string");
        n=0;
        while((buffer[n++]=getchar())!='\n'){
            write(socketfd, buffer, sizeof(buffer));
            bzero(buffer,sizeof(buffer));
            read(socketfd,buffer,sizeof(buffer));
            printf("From server");
            if(strcmp(buffer,"exit")==0){
                printf("Client exit");
                break;
            }
        }
    }
}