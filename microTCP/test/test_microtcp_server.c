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
    int data;
    int data1;
    void *buf[1024];
    char buffer[1024];
    char array[10000];
    microtcp_header_t header;
    microtcp_sock_t socket;
    struct sockaddr_in servaddr, clientaddr;

    printf("Listening on port 8080..\n ");

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
    int data_recv = 0, data_r = 0;

    while (data1 = microtcp_recv(&socket, (char *)array, 10000, MSG_WAITALL))
    {
        //if (socket.state != DUP_ACK)
        printf("data1 received :  %d\n", data1);

        data_r += data1;
    }
    printf("data received :  %d\n", data_r);

    microtcp_shutdown(&socket, 1);

    return 0;
}

/*
    while (data = microtcp_recv(&socket, (char *)buffer, 1024, MSG_WAITALL))
    {
        data_recv += data;
        printf("data received :  %d\n", data_recv);
        printf("Client's message: %s\n", buffer);
    }
    buffer[data_recv] = '\0';
*/
