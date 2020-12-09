/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../lib/microtcp.h"
#define MAXLINE 1024

int main(int argc, char **argv)
{
    microtcp_header_t header;
    int data;
    microtcp_sock_t socket;
    int sockfd, connfd, len;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr, clientaddr;
    void *helloser = "Hello from server.";
    printf("listening on port 8080..\n ");

    socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&clientaddr, 0, sizeof(clientaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8080);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    if (microtcp_bind(&socket, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("Bind failed.\n");
        exit(EXIT_FAILURE);
    }
    microtcp_accept(&socket, (struct sockaddr *)&clientaddr, sizeof(clientaddr));


    memset(&header, 0, sizeof(header));

    while (data = microtcp_recv(&socket, &header, sizeof(header), MSG_WAITALL))
    {
        printf("RECEIVE: seq-> %d, ack->%d, control->%d\n", header.seq_number, header.ack_number, header.control);
    }
    microtcp_shutdown(&socket, 1);

    return 0;
}

/*    microtcp_header_t header;

    microtcp_recv(&socket, &header, sizeof(header), MSG_WAITALL);
    printf("header recieved with sequence number : %d \n", header.seq_number);    
 */