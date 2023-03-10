#include"cJSON.h"
#include"cJSON.c"
#include<stdio.h>
#include<stdlib.h>
void main(int argc, char *args[]){
    if(argc<2){
        printf("Insufficient arguments. Please provide config file.\n");
        return;
    }
    char* config_path = args[1];
    read_config_file(config_path);
    
}
void read_config_file(char* path){
    FILE* fp;
    char buffer[1024];
    // Opening file in reading mode
    fp = fopen(path, "r");
    fread(buffer,1024,1,fp);
    cJSON* json = cJSON_Parse(buffer);
    char* string = cJSON_Print(json);
    printf("%s", string);
    fclose(fp);
    const cJSON *ttl = NULL;
    ttl =  cJSON_GetObjectItemCaseSensitive(json, "time_to_live");
    printf("\n%s", ttl->valuestring);
}