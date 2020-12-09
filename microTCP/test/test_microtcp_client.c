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
 * You can use this file to write a test microTCP client.
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
    microtcp_header_t header1, header2, header3;
    microtcp_sock_t socket_cl;
    int sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in clientaddr;
    void *hellocl = "Hello from client.";

    socket_cl = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    memset(&clientaddr, 0, sizeof(clientaddr));

    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(8080);
    clientaddr.sin_addr.s_addr = INADDR_ANY;

    microtcp_connect(&socket_cl, (const struct sockaddr *)&clientaddr, sizeof(clientaddr));

    memset(&header1, 0, sizeof(header1));
    memset(&header2, 0, sizeof(header2));
    memset(&header3, 0, sizeof(header3));

    header1.control = 1; header1.seq_number = 130; header1.ack_number = 456;
    header2.control = 4; header2.seq_number = 75; header2.ack_number = 112;
    header3.control = 9; header3.seq_number = 13; header3.ack_number = 721;

    microtcp_send(&socket_cl, &header1, sizeof(header1), 0);
    microtcp_send(&socket_cl, &header2, sizeof(header2), 0);
    microtcp_send(&socket_cl, &header3, sizeof(header3), 0);

    microtcp_shutdown(&socket_cl, 1);

    close(socket_cl.sd);

    return 0;
}

/*
    if (bind(socket_cl->sd, (const struct sockaddr *)&clientaddr, sizeof(clientaddr)) < 0)
    {
        perror("Bind failed.\n");
        exit(EXIT_FAILURE);
    }
*/

/*
     microtcp_header_t header;
    // microtcp_header_t * head;
   
    memset(&header, 0, sizeof(header));
    header.seq_number = 3;
    //head=&header;
    int sent = microtcp_send(&socket_cl, &header, sizeof(header), 0);
    if (sent == -1)
    {
        printf("Error sending\n");
    }
    */