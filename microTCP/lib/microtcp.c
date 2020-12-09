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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

int errno;

uint16_t my_modifyBit(uint16_t n, uint16_t p, uint16_t b)
{
  uint16_t mask = 1 << p;
  return (n & ~mask) | ((b << p) & mask);
}

int random_func()
{
  srand(getpid());

  return rand();
}

void print_binary(uint16_t x)
{
  printf("Updated control: %d\n", x);
}

microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
  microtcp_sock_t newSocket;

  if ((newSocket.sd = socket(domain, type, protocol)) < 0)
  {
    newSocket.state = INVALID;
    perror("Creating socket error.\n");
    exit(EXIT_FAILURE);
  }

  newSocket.state = UNKNOWN;

  return newSocket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{

  socket->state = LISTEN;
  return bind(socket->sd, address, address_len);
}

socklen_t add_len;

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  add_len = address_len;
  microtcp_header_t header;

  memset(&header, 0, sizeof(header));
  socket->dest_addr = (struct sockaddr *)address;
  int random = random_func();
  header.seq_number = random;
  header.control = my_modifyBit(header.control, 1, 1);

  printf("1st send from client: seq_num %d ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);
  int sent1_cl = microtcp_send(socket, &header, sizeof(header), 0);
  if (sent1_cl == -1)
  {
    printf("Error sending: %i\n", errno);
  }

  int n = microtcp_recv(socket, &header, sizeof(header), MSG_WAITALL);
  if (n < 0)
  {
    printf("Receive error: %i\n", errno);
  }

  printf("2nd receive from server: seq_num %d and ack_num %d\nWith control: %d\n", header.seq_number, header.ack_number, header.control);

  header.seq_number = header.ack_number;
  header.ack_number = header.seq_number + 1;
  header.control = my_modifyBit(header.control, 1, 0);

  printf("2nd send from client: seq_num %d ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

  int sent2_cl = microtcp_send(socket, &header, sizeof(header), 0);
  if (sent2_cl == -1)
  {
    printf("Error sending: %i\n", errno);
  }

  socket->state = ESTABLISHED;
  return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  add_len = address_len;

  microtcp_header_t header;
  memset(&header, 0, sizeof(header));

  socket->dest_addr = address;
  int n = microtcp_recv(socket, &header, sizeof(header), MSG_WAITALL);
  if (n < 0)
  {
    printf("Receive error: %i\n", errno);
  }

  printf("1st receive from server: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

  header.ack_number = header.seq_number + 1;
  header.seq_number = random_func();
  uint16_t newControl = header.control;
  header.control = my_modifyBit(newControl, 3, 1);

  printf("2nd send from server: seq_num %d and ack_num %d\nWith control: %d\n", header.seq_number, header.ack_number, header.control);

  int sent_serv = microtcp_send(socket, &header, sizeof(header), 0);
  if (sent_serv == -1)
  {
    printf("Error sending: %i\n", errno);
  }

  int n2 = microtcp_recv(socket, &header, sizeof(header), MSG_WAITALL);
  if (n2 < 0)
  {
    printf("Receive error: %i\n", errno);
  }

  printf("2nd receive from server: seq_num %d and ack_num %d\nWith control: %d\n", header.seq_number, header.ack_number, header.control);

  return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  microtcp_header_t header;
  memset(&header, 0, sizeof(header));

  microtcp_header_t header2;
  memset(&header2, 0, sizeof(header2));

  if (socket->state == CLOSING_BY_HOST)
  {
    printf("HOST SHUTDOWN..\n");
    int n = microtcp_recv(socket, &header, sizeof(header), MSG_WAITALL);
    if (n < 0)
    {
      printf("Receive error: %i\n", errno);
    }

    printf("1strecv server: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

    header.ack_number = header.seq_number + 1;
    header.control = my_modifyBit(header.control, 0, 0);

    int sent_1 = microtcp_send(socket, &header, sizeof(header), 0);
    if (sent_1 == -1)
    {
      printf("Error sending: %i\n", errno);
    }
    printf("1st send server: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

    header2.seq_number = random_func();
    header2.control = my_modifyBit(header2.control, 0, 1);
    header2.control = my_modifyBit(header2.control, 3, 1);

    int sent_2 = microtcp_send(socket, &header2, sizeof(header2), 0);
    if (sent_2 == -1)
    {
      printf("Error sending: %i\n", errno);
    }

    printf("2nd send server: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);

    int n2 = microtcp_recv(socket, &header2, sizeof(header2), MSG_WAITALL);
    if (n2 < 0)
    {
      printf("Receive error: %i\n", errno);
    }

    printf("2nd recv server: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);

    socket->state = CLOSED;
  }
  else
  {
    printf("CLIENT SHUTDOWN..\n");

    header.seq_number = random_func();
    header.control = my_modifyBit(header.control, 0, 1);
    header.control = my_modifyBit(header.control, 3, 1);

    int sent1 = microtcp_send(socket, &header, sizeof(header), 0);
    if (sent1 == -1)
    {
      printf("Error sending: %i\n", errno);
    }

    printf("1st send client: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

    int r1 = microtcp_recv(socket, &header, sizeof(header), MSG_WAITALL);
    if (r1 < 0)
    {
      printf("Receive error: %i\n", errno);
    }

    printf("1st recv client: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

    socket->state = CLOSING_BY_PEER;

    int r2 = microtcp_recv(socket, &header2, sizeof(header2), MSG_WAITALL);
    if (r2 < 0)
    {
      printf("Receive error: %i\n", errno);
    }
    printf("2nd recv client: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);

    header2.ack_number = header2.seq_number + 1;
    header2.seq_number = header.ack_number;
    header2.control = my_modifyBit(header2.control, 0, 0);

    int sent2 = microtcp_send(socket, &header2, sizeof(header2), 0);
    if (sent2 == -1)
    {
      printf("Error sending: %i\n", errno);
    }

    printf("2nd send client: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);
  }
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  int bytes_send = sendto(socket->sd, buffer, length, flags, socket->dest_addr, add_len);

  return bytes_send;
}
ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  microtcp_header_t *header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));

  int len = sizeof(add_len);
  int bytes_recv = recvfrom(socket->sd, buffer, length, flags, socket->dest_addr, &len);

  memcpy(header, buffer, length);
  if (header->control == 9)
  {
    socket->state = CLOSING_BY_HOST;

    return 0;
  }
  
  return bytes_recv;
}