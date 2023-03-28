CS-621 : End-to-End Detection of Network Compression
Author : Gandhar Kulkarni

Project Overview
================
This project is designed to detect network compression through the use of 1) client-server application and 2) Standalone application.

1) Client-Server application operates on two seperate machines and communicates through sockets. The client sends data to the server through series of UDP packets
and the server detects if there is any presence of network compression.

2) Standalone application operates on a single machine. The client sends data to an unresponsive server and determines the presence of network compression based on
standard network events.

This project is inspired by the work :
https://www.cs.usfca.edu/vahab/resources/compression_detection.pdf

Requirements
============
Ubuntu machines are required to run this program. A JSON configuration file is required in the specified format.


Installation
=============
No specific installation is required to run this program.

Configuration File
==================
A JSON configuration file is required to run this program. The configuration file must be in following format. 
If you expect to use default value, enter 0 in respective field, the program will automatically use default values for the field.
{
    "server_ip":"10.0.0.251", //The Server’s IP Address
    "source_port_udp":9876, //Source Port Number for UDP
    "destination_port_udp":8765, //Destination Port Number for UDP
    "destination_port_tcp_head_syn": 5757, //Destination Port Number for TCP Head SYN, x
    "destination_port_tcp_tail_syn": 7575, //Destination Port Number for TCP Tail SYN, y
    "tcp_port":8787, //Port Number for TCP (Pre-/Post- Probing Phases)
    "udp_payload_size":1000, //The Size of the UDP Payload in the UDP Packet Train, (default value: 1000B)
    "inter_measurement_time":15, //Inter-Measurement Time, γ (default value: 15 seconds)
    "udp_packets":6000, //The Number of UDP Packets in the UDP Packet Train, n (default value: 6000 )
    "time_to_live":255 //TTL for the UDP Packets (default value: 255 )
}

Client-Server Application
=========================
The application has 2 hosts, client & server. The hosts communicate through sockets in order to check if network compression exists. 
There are three phases in this process.

    Pre-Probing Phase
    =================
    First, the server initiates a TCP socket and associates it with a port. Then, it waits for incoming client connections. 
    At the same time, the client processes the data from the given configuration file. 
    Afterwards, the client initializes its own socket and establishes a link with the server. 
    After the connection is established, the client transmits the configuration data to the server over tcp connection, which then interprets the received data. 
    Now, both the server and the client application can access the data.

    Probing Phase
    =============
    The server establishes a UDP socket and configures it to receive a specific number of UDP packets from the client. 
    On the other hand, the client creates an array of bytes containing low entropy data (all 0s) and generates the same number of UDP packets required by the server. 
    After setting the packet IDs for each section in the array and enabling the don't-fragment bit, the packets are consecutively transmitted to the server. 
    The program then waits for the designated inter-measurement time before repeating the process with high entropy data. 
    This is achieved by replacing the array's low entropy data with random data generated from "/dev/urandom", setting the packet IDs again, and sending the packets back-to-back to the server.

    In the meantime, the server is continually accepting packets from the client. First, it waits for all the low-entropy data to arrive and then for the high-entropy data. 
    The server application measures the time difference between the beginning and end of the low- and high-entropy packet trains' arrivals. 
    It then compares the difference in time (time of high entropy data - time of low entropy data) to 100 milliseconds. If the result exceeds 100ms, the server concludes that network compression has occurred; otherwise, no network compression has been detected.


    Post-Probing Phase
    ==================
    The client sleeps for 2 seconds before server completes the computation and initiates a TCP socket and associates it with a port. (If server computation is not completed, may have to increase the sleep interval)
    The client then establishes a connection with the server, who, after accepting the connection from the client, shares the finding about network compression 
    back to the client. The client displays the results of the investigation (whether network compression was detected or not) and connection is terminated.

    Execute Program
    ================
    Client :
        compile : gcc -g -std=c99 -o client client.c
        run :  ./client ./config.json
    Server: 
        compile : gcc -g -std=c99 -o server server.c
        run : ./server 8787

Standalone Application
======================
The aim of the standalone application is to detect network compression by sending customized TCP SYN packets to an unresponsive server and measuring the time interval between the server's responses in the form of TCP RST packets.
The standalone application employs a raw socket to send the TCP packets, and creates custom IP headers and TCP headers for each packet using data from the configuration file. The checksums for the headers are calculated and the SYN flag is set in the TCP header. The standalone program then transmits the TCP packet to the server. 

Following this, the program creates a train of low entropy UDP packets, sets the UDP packet time to live value from the configuration file, and sends them to the server. After sending the final UDP packet, the program creates a tail TCP packet similar to the first one and sends it to the server as well.
After waiting for the inter-measurement time, the program repeats the process with high entropy data. 

It creates and sends the head TCP packet, constructs and sends the high entropy packets, and creates and sends the tail TCP packet.

While these packets are being constructed and sent, a different thread is created to listen for TCP RST packets from the server. 
The thread uses the recv() method to capture any incoming packets and decides if the packet is the expected RST based on specified source and destination port number.
The thread process calculates the time between the arrival of each RST packet. The time interval between the arrival of the first RST packet and the second RST packet is calculated for both low and high entropy data. 
If a timeout occurs due to a delay or absence of an RST packet from the server, the application terminates due to insufficient information.

The difference between these times is compared to the 100ms threshold, and the outcome is displayed. Finally, the program terminates.
    
    **Note: If you face error 'socket() failed to get socket descriptor for using ioctl() : Operation not permitted' error. Run the code with sudo privileges.
    Make sure to change mac address at line# 499 - 504, if need to point to different server.

    Execute Program
    ================
    compile :
        gcc standalone.c -o standalone
    run : 
        ./standalone ./config.json

        //if 'Operation not permitted' error occurs, sudo privileges are required
        sudo ./standalone ./config.json 


