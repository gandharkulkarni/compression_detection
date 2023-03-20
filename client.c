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
#include<arpa/inet.h>
#define SA struct sockaddr
int tcp_sockfd, udp_sockfd;
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
struct config* config;
struct cJSON *read_config(char* path){
    FILE* fp;
    char buffer[1024];

    /* Opening file in reading mode */
    fp = fopen(path, "r");
    fread(buffer,1024,1,fp);

    /* Parse json file */
    cJSON* json = cJSON_Parse(buffer);
    fclose(fp);
    return json;
}
void close_tcp_connection(){
    close(tcp_sockfd);
}
void get_config_struct(cJSON* json){
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

    /* Create config struct */
    config = malloc(sizeof *config);
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
}
void connect_to_server(){
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
 
    /* socket create for TCP connection */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
 
    /* assign IP, PORT */
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(config->server_ip);
    servaddr.sin_port = htons(config->tcp_port);
 
    /* connect the client socket to server socket */
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))
        != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
    tcp_sockfd = sockfd;
    // char buffer[1024];
    // int n;
    // bzero(buffer,sizeof(buffer));
    // n=0;
    // strcpy(buffer,msg);
    // write(sockfd, buffer, sizeof(buffer));
    // bzero(buffer,sizeof(buffer));
    // read(sockfd, buffer, sizeof(buffer));
    // printf("Server response: %s\n", buffer);
    // close(sockfd);
}
void send_config_to_server(char * config){
    char buffer[1024];
    bzero(buffer,sizeof(buffer));
    strcpy(buffer,config);
    write(tcp_sockfd, buffer, sizeof(buffer));
    bzero(buffer,sizeof(buffer));
    read(tcp_sockfd, buffer, sizeof(buffer));
    printf("Server response: %s\n", buffer);
}
void get_test_results_from_server(){
    char buffer[1024];
    bzero(buffer,sizeof(buffer));
    read(tcp_sockfd, buffer, sizeof(buffer));
    printf("Server response: %s\n", buffer);
}
void send_udp_packets_to_server(){
    int sockfd;
    char buffer[config->udp_payload_size];
    struct sockaddr_in servaddr, cliaddr;
    memset(buffer, 0, config->udp_payload_size);
    float threshold = 100;
    
    /* Creating socket for UDP connection */
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(config->destination_port_udp);
    servaddr.sin_addr.s_addr = inet_addr(config->server_ip);
    
    cliaddr.sin_family = AF_INET;
    cliaddr.sin_port = htons(config->source_port_udp);


    if(bind(sockfd, (struct sockaddr *) &cliaddr, sizeof(cliaddr)) < 0){
		printf("bind failed\n");
		exit(EXIT_FAILURE);
	}

    int df_bit = IP_PMTUDISC_DO;
    
    /* set DF bit*/
    if(setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &df_bit, sizeof(df_bit))<0){
        printf("Unable to set DF bit");
        exit(EXIT_FAILURE);
    }

    printf("Sending...");
    int i;
    /* sending udp packet train for low entropy */
    for(i=0; i<config->udp_packets; i++){
        buffer[0] = (i >> 8) & 0xFF;
        buffer[1] = i & 0xff;

        int n = sendto(sockfd, (char *)buffer, sizeof(buffer),
            MSG_CONFIRM, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
            if(i%1000==0){
                printf("Sent %d packets. Code : %d\n", i, n);
            }
    }
    printf("Low entropy UDP packets sent.\n\n");

	printf("Waiting for %d seconds between tests.\n\n", config->inter_measurement_time);
	/* sleep for inter-measurement time */
	sleep(config->inter_measurement_time);

    FILE* fp;
    fp = fopen("highEntropyData", "r");
    memset(buffer, 0, config->udp_payload_size);
    fread(buffer,config->udp_payload_size,1,fp);
    fclose(fp);
    
    /* sending udp packet train for high entropy */
    for(i=0; i<config->udp_packets; i++){
        buffer[0] = (i >> 8) & 0xFF;
        buffer[1] = i & 0xff;

        int n = sendto(sockfd, (char *)buffer, sizeof(buffer),
            MSG_CONFIRM, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
            if(i%1000==0){
                printf("Sent %d packets. Code : %d\n", i, n);
            }
    }
    close(sockfd);
}
void main(int argc, char *args[]){
    if(argc<2){
        printf("Insufficient arguments. Please provide config file.\n");
        return;
    }
    /*Get config file path from arg*/
    char* config_path = args[1];

    /*Read config file and get cJSON object*/
    cJSON* json = read_config(config_path);

    /*Get config values into struct*/
    get_config_struct(json);

    /*Get config file in a string format*/
    char * json_str = cJSON_Print(json);

    /*Pre probing : Send config file to server*/
    connect_to_server();
    send_config_to_server(json_str);
    close_tcp_connection();
    
    send_udp_packets_to_server();

    sleep(7);
    connect_to_server();
    get_test_results_from_server();
    close_tcp_connection();

}
void print_config(){
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
}