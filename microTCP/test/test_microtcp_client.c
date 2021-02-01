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

void arrayOfChars(char *buf, int length, char a)
{
    for (int i = 0; i < length; i++)
    {
        buf[i] = a;
    }
    buf[length] = '\0';
}

int main(int argc, char **argv)
{
    void *buffer[1024];
    microtcp_header_t header1, header2, header3;
    microtcp_sock_t socket_cl;
    struct sockaddr_in clientaddr;
    char array[10000];
    char *hello = "Hello";

    socket_cl = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    memset(&clientaddr, 0, sizeof(clientaddr));

    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(8080);
    clientaddr.sin_addr.s_addr = INADDR_ANY;

    microtcp_connect(&socket_cl, (const struct sockaddr *)&clientaddr, sizeof(clientaddr));

    arrayOfChars(array, 10000, 'a');

    microtcp_send(&socket_cl, (const char *)array, 10000, 0);

    printf("Message sent from client.\n");

    microtcp_shutdown(&socket_cl, 1);

    close(socket_cl.sd);

    return 0;
}

// microtcp_send(&socket_cl, (const char *)hello, 6, 0);
// int m = microtcp_recv(&socket_cl, (char *)buffer, 1024, 0);
// buffer[m] = '\0';
