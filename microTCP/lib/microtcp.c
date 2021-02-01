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
#define min(a, b) (((a) < (b)) ? (a) : (b))

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
#include <math.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

int errno;

ssize_t my_min(size_t a, size_t b, size_t c)
{
  return min(a, min(b, c));
}

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

int errorCheck(microtcp_sock_t *socket, microtcp_header_t *header, int length)
{
  long int tempChecksum = header->checksum;
  printf("Initial checksum = %d\n", header->checksum);

  header->checksum = 0;
  header->checksum = crc32((uint8_t *)header, sizeof(microtcp_header_t));
  printf("Computed checksum = %d\n", header->checksum);

  if (tempChecksum != header->checksum)
  {
    perror("ERROR: Not the same checksum\n");
    return -1;
  }
  else
  {
    printf("Same checksum\n");
  }
}

int correctOrder(microtcp_sock_t *socket, microtcp_header_t header, int length)
{
  size_t tempSeq = 0;

  tempSeq = header.seq_number;

  if (tempSeq != (header.ack_number - 1))
  {
    perror("ERROR: Not the same sequence\n");
    return -1;
  }
  else
  {
    printf("Correct receipt of sequence\n");
    return 0;
  }
}

microtcp_header_t hton_func(microtcp_header_t header)
{
  header.seq_number = htonl(header.seq_number);
  header.ack_number = htonl(header.ack_number);
  header.control = htons(header.control);
  header.window = htons(header.window);
  header.data_len = htonl(header.data_len);
  header.future_use0 = htonl(header.future_use0);
  header.future_use1 = htonl(header.future_use1);
  header.future_use2 = htonl(header.future_use2);
  header.checksum = htonl(header.checksum);

  return header;
}

microtcp_header_t ntoh_func(microtcp_header_t header)
{
  header.seq_number = ntohl(header.seq_number);
  header.ack_number = ntohl(header.ack_number);
  header.control = ntohs(header.control);
  header.window = ntohs(header.window);
  header.data_len = ntohl(header.data_len);
  header.future_use0 = ntohl(header.future_use0);
  header.future_use1 = ntohl(header.future_use1);
  header.future_use2 = ntohl(header.future_use2);
  header.checksum = ntohl(header.checksum);

  return header;
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
  newSocket.init_win_size = MICROTCP_WIN_SIZE;
  newSocket.curr_win_size = MICROTCP_WIN_SIZE;

  newSocket.ssthresh = MICROTCP_INIT_SSTHRESH;
  newSocket.cwnd = MICROTCP_INIT_CWND;

  return newSocket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{

  socket->state = LISTEN;
  return bind(socket->sd, address, address_len);
}

socklen_t add_len;
static int found3DA = 0;
static int dupAcks = 0;
static int crash = 0;

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  printf("-----------------------\n");
  printf("HANDSHAKE..\n\n");

  add_len = address_len;
  microtcp_header_t header;
  uint32_t tempSeq = 0;

  long int check0, check1;

  memset(&header, 0, sizeof(header));
  socket->dest_addr = (struct sockaddr *)address;

  int random = random_func();
  header.seq_number = random;
  tempSeq = header.seq_number;
  header.control = my_modifyBit(header.control, 1, 1);
  header.window = MICROTCP_WIN_SIZE;
  header.checksum = 0;
  check0 = crc32((uint8_t *)&header, sizeof(microtcp_header_t));
  header.checksum = check0;

  printf("1st send from client: seq_num %d ack_num %d checksum %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.checksum, header.control);

  header = hton_func(header);

  int sent1_cl = microtcp_send_header(socket, &header, sizeof(header), 0);
  if (sent1_cl == -1)
  {
    printf("Error sending: %i\n", errno);
  }

  int n = microtcp_recv_header(socket, &header, sizeof(header), MSG_WAITALL);
  if (n < 0)
  {
    printf("Receive error: %i\n", errno);
  }

  header = ntoh_func(header);

  printf("1st receive from client: seq_num %d ack_num %d checksum %d\nWith control: %d\n", header.seq_number, header.ack_number, header.checksum, header.control);
  errorCheck(socket, &header, sizeof(microtcp_header_t));
  if (tempSeq != (header.ack_number - 1))
  {
    perror("Wrong receipt of packets\n");
  }
  else
  {
    printf("Correct receipt of packets\n");
  }

  uint32_t temp = header.seq_number;

  socket->curr_win_size = header.window;
  header.seq_number = header.ack_number;
  header.ack_number = temp + 1;
  header.control = my_modifyBit(header.control, 1, 0);
  header.checksum = 0;
  check0 = crc32((uint8_t *)&header, sizeof(microtcp_header_t));
  header.checksum = check0;

  printf("2nd send from client: seq_num %d ack_num %d checksum %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.checksum, header.control);

  socket->seq_number = header.seq_number;
  socket->ack_number = header.ack_number;
  socket->control = header.control;
  socket->curr_win_size = MICROTCP_WIN_SIZE;

  header = hton_func(header);

  int sent2_cl = microtcp_send_header(socket, &header, sizeof(header), 0);
  if (sent2_cl == -1)
  {
    printf("Error sending: %i\n", errno);
  }

  printf("%ld seq of socket, %ld ack of socket\n", socket->seq_number, socket->ack_number);

  socket->state = ESTABLISHED;
  socket->recvbuf = malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;

  return 0;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  printf("-----------------------\n");
  printf("HANDSHAKE..\n\n");

  add_len = address_len;
  uint32_t tempSeq = 0;
  long int checksum;

  microtcp_header_t header;
  memset(&header, 0, sizeof(microtcp_header_t));

  socket->dest_addr = (struct sockaddr *)address;
  int n = microtcp_recv_header(socket, &header, sizeof(header), MSG_WAITALL);
  if (n < 0)
  {
    printf("Receive error: %i\n", errno);
  }

  header = ntoh_func(header);

  printf("1st receive from server: seq_num %d and ack_num %d checksum %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.checksum, header.control);
  errorCheck(socket, &header, sizeof(microtcp_header_t));

  header.ack_number = header.seq_number + 1;

  header.seq_number = random_func();
  tempSeq = header.seq_number;

  uint16_t newControl = header.control;
  header.control = my_modifyBit(newControl, 3, 1);
  header.window = MICROTCP_WIN_SIZE;
  header.checksum = 0;
  checksum = crc32((uint8_t *)&header, sizeof(microtcp_header_t));
  header.checksum = checksum;

  printf("2nd send from server: seq_num %d and ack_num %d checksum %d\nWith control: %d\n", header.seq_number, header.ack_number, header.checksum, header.control);

  header = hton_func(header);

  int sent_serv = microtcp_send_header(socket, &header, sizeof(header), 0);
  if (sent_serv == -1)
  {
    printf("Error sending: %i\n", errno);
  }

  int n2 = microtcp_recv_header(socket, &header, sizeof(header), MSG_WAITALL);
  if (n2 < 0)
  {
    printf("Receive error: %i\n", errno);
  }

  header = ntoh_func(header);

  printf("2nd receive from server: seq_num %d ack_num %d checksum %d\nWith control: %d\n", header.seq_number, header.ack_number, header.checksum, header.control);
  errorCheck(socket, &header, sizeof(microtcp_header_t));
  if (tempSeq != (header.ack_number - 1))
  {
    perror("Wrong receipt of packets\n");
  }
  else
  {
    printf("Correct receipt of packets\n");
  }

  socket->seq_number = header.ack_number;
  socket->ack_number = header.seq_number;
  socket->recvbuf = malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level = 0;
  return 0;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  microtcp_header_t header;
  memset(&header, 0, sizeof(header));

  microtcp_header_t header2;
  memset(&header2, 0, sizeof(header2));

  uint32_t tempSeq = 0;

  if (socket->state == CLOSING_BY_PEER)
  {
    printf("HOST ENTERS SHUTDOWN..\n\n");

    header.seq_number = socket->seq_number;
    header.ack_number = header.seq_number + 1;

    correctOrder(socket, header, sizeof(header));

    header.checksum = 0;
    header.control = socket->control;
    header.control = my_modifyBit(header.control, 0, 0);

    printf("1st send server: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

    header = hton_func(header);

    int sent_1 = microtcp_send_header(socket, &header, sizeof(header), 0);
    if (sent_1 == -1)
    {
      printf("Error sending: %i\n", errno);
    }

    header2.seq_number = random_func();
    tempSeq = header2.seq_number;
    header2.control = my_modifyBit(header2.control, 0, 1);
    header2.control = my_modifyBit(header2.control, 3, 1);
    header2.checksum = 0;

    printf("2nd send server: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);

    header2 = hton_func(header2);

    int sent_2 = microtcp_send_header(socket, &header2, sizeof(header2), 0);
    if (sent_2 == -1)
    {
      printf("Error sending: %i\n", errno);
    }

    int n2 = microtcp_recv_header(socket, &header2, sizeof(header2), MSG_WAITALL);
    if (n2 < 0)
    {
      printf("Receive error: %i\n", errno);
    }

    header2 = ntoh_func(header2);

    printf("2nd recv server: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);
    if (tempSeq != (header2.ack_number - 1))
    {
      perror("Wrong receipt of packets\n");
    }
    else
    {
      printf("Correct receipt of packets\n");
    }

    socket->state = CLOSED;
  }
  else
  {
    printf("-----------------------\n");
    printf("CLIENT SHUTDOWN..\n");

    header.seq_number = random_func();
    header.control = my_modifyBit(header.control, 0, 1);
    header.control = my_modifyBit(header.control, 3, 1);
    header.checksum = 0;

    printf("1st send client: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);

    header = hton_func(header);

    int sent1 = microtcp_send_header(socket, &header, sizeof(header), 0);
    if (sent1 == -1)
    {
      printf("Error sending: %i\n", errno);
    }

    int r1 = microtcp_recv_header(socket, &header, sizeof(header), MSG_WAITALL);
    if (r1 < 0)
    {
      printf("Receive error: %i\n", errno);
    }

    header = ntoh_func(header);

    printf("1st recv client: seq_num %d and ack_num %d\nWith control: %hu\n", header.seq_number, header.ack_number, header.control);
    correctOrder(socket, header, sizeof(header));

    socket->state = CLOSING_BY_PEER;

    int r2 = microtcp_recv_header(socket, &header2, sizeof(header2), MSG_WAITALL);
    if (r2 < 0)
    {
      printf("Receive error: %i\n", errno);
    }

    header2 = ntoh_func(header2);

    printf("2nd recv client: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);

    header2.ack_number = header2.seq_number + 1;

    correctOrder(socket, header2, sizeof(header2));

    header2.seq_number = header.ack_number;
    header2.control = my_modifyBit(header2.control, 0, 0);
    header2.checksum = 0;

    printf("2nd send client: seq_num %d and ack_num %d\nWith control: %hu\n", header2.seq_number, header2.ack_number, header2.control);

    header2 = hton_func(header2);

    int sent2 = microtcp_send_header(socket, &header2, sizeof(header2), 0);
    if (sent2 == -1)
    {
      printf("Error sending: %i\n", errno);
    }
  }
}

ssize_t
microtcp_send_header(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  int bytes_send = sendto(socket->sd, buffer, length, flags, socket->dest_addr, add_len);

  return bytes_send;
}

ssize_t
microtcp_recv_header(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  microtcp_header_t *header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));

  // int len = sizeof(add_len);
  int bytes_recv = recvfrom(socket->sd, buffer, sizeof(microtcp_header_t), flags, socket->dest_addr, &add_len);

  memcpy(header, buffer, sizeof(microtcp_header_t));

  if (header->control == 9)
  {
    socket->seq_number = header->seq_number;
    socket->ack_number = header->ack_number;
    socket->control = header->control;
    socket->state = CLOSING_BY_PEER;

    return -1;
  }

  return bytes_recv;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  size_t chunks = 0, remaining = 0, data_sent = 0, bytes_to_send = 0, semiPack = 0;
  size_t data_sent_correctly = 0;
  int numOfAcks = 0, numOfPackets = 0;
  int erCh = 0;

  size_t i = 0;
  int bytes_recv = 0, bytes_send = 0;
  long int Check0, Check1;
  int bytes_sent = 0, bytes_sent1 = 0;

  uint32_t tempSeq = socket->seq_number, tempAck = socket->ack_number;
  long int tempCheck0 = 0, tempCheck1 = 0;
  uint16_t flow_ctrl_win;

  microtcp_header_t header_send, header_recv, header_check;

  memset(&header_send, 0, sizeof(microtcp_header_t));
  memset(&header_recv, 0, sizeof(microtcp_header_t));
  memset(&header_check, 0, sizeof(microtcp_header_t));

  char *data = malloc((MICROTCP_MSS + sizeof(microtcp_header_t)) * sizeof(char));

  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

  header_send.window = MICROTCP_RECVBUF_LEN;
  flow_ctrl_win = header_send.window;

  data_sent = 0;
  remaining = length;

  while (data_sent < length)
  {
    printf("-----------------------\n");
    printf("Start sending chunks..\n\n");
    bytes_to_send = my_min(flow_ctrl_win, socket->cwnd, remaining);
    chunks = bytes_to_send / MICROTCP_MSS;

    for (i = 0; i < chunks; i++)
    {
      printf("-----------------------\n");
      printf("Packet case 1\n");
      header_send.data_len = bytes_to_send;
      header_send.seq_number = tempSeq;
      header_send.ack_number = tempAck;

      printf("\tSENDING(1): Sending Sequence = %d\n\tSENDING(1): Sending Ack = %d\n", header_send.seq_number, header_send.ack_number);

      header_send.checksum = 0;

      memcpy(data, &header_send, sizeof(microtcp_header_t));
      memcpy((data + sizeof(microtcp_header_t)), buffer + data_sent, MICROTCP_MSS);

      tempCheck0 = (long int)crc32((uint8_t *)data, MICROTCP_MSS + sizeof(microtcp_header_t));
      header_send.checksum = tempCheck0;
      printf("\tSENDING(1): Sending Checksum = %ld\n", tempCheck0);

      header_send = hton_func(header_send);
      memcpy(data, &header_send, sizeof(microtcp_header_t));

      if ((bytes_sent1 = sendto(socket->sd, data, MICROTCP_MSS + sizeof(microtcp_header_t), flags, socket->dest_addr, add_len)) < 0)
      {
        socket->state = INVALID;
        printf("ERROR IN SEND: Couldn't send packet.\n");
        return -1;
      }
      printf("\tSENDING(1): Sending %d bytes.\n\n", bytes_sent1);

      tempSeq += MICROTCP_MSS;
      tempAck += 1;
      numOfPackets++;
      //data_sent = data_sent + MICROTCP_MSS;
    }
    /* Check if there is a semi -filled chunk */
    if (bytes_to_send % MICROTCP_MSS)
    {
      printf("-----------------------\n");
      printf("Packet case 2\n");
      chunks++;

      semiPack = bytes_to_send % MICROTCP_MSS;

      header_send.data_len = bytes_to_send;
      header_send.seq_number = tempSeq;
      header_send.ack_number = tempAck;

      printf("\tSENDING(2): Sending Sequence = %d\n\tSENDING(2): Sending Ack = %d\n", header_send.seq_number, header_send.ack_number);

      header_send.checksum = 0;

      memcpy(data, &header_send, sizeof(microtcp_header_t));
      memcpy((data + sizeof(microtcp_header_t)), buffer + data_sent, MICROTCP_MSS);

      tempCheck0 = crc32((uint8_t *)data, semiPack + sizeof(microtcp_header_t));
      header_send.checksum = tempCheck0;
      printf("\tSENDING(2): Sending Checksum = %ld\n", (long int)header_send.checksum);

      header_send = hton_func(header_send);
      memcpy(data, &header_send, sizeof(microtcp_header_t));

      if ((bytes_sent = sendto(socket->sd, data, semiPack + sizeof(microtcp_header_t), flags, socket->dest_addr, add_len)) < 0)
      {
        socket->state = INVALID;
        printf("ERROR IN SEND: Couldn't send packet.\n");
        return -1;
      }
      printf("\tSENDING(2): Sending %d bytes.\n", bytes_sent);

      tempSeq += semiPack;
      tempAck += 1;

      numOfPackets++;
      //data_sent = data_sent + semiPack;
    }

    /* Get the ACKs */
    for (i = 0; i < chunks; i++)
    {
      printf("\n-----------------------\n");
      printf("Checking for ACK..\n\n");
      if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
      {
        printf("ERROR IN SEND: Time out.\n");

        socket->ssthresh = socket->cwnd / 2;
        socket->cwnd = min(MICROTCP_MSS, socket->ssthresh);

        continue;
      }

      int len = sizeof(add_len);
      bytes_recv = microtcp_recv_header(socket, &header_recv, sizeof(microtcp_header_t), 0);
      if (bytes_recv < 0)
      {
        socket->state = INVALID;
        printf("ERROR IN SEND: ACK not received\n");
        break;
      }

      numOfAcks++;

      header_recv = ntoh_func(header_recv);

      printf("IN SEND: Received ACK with Seq = %d, Ack = %d, Checksum = %ld\n", header_recv.seq_number, header_recv.ack_number, (long int)header_recv.checksum);
      if ((erCh = errorCheck(socket, &header_recv, sizeof(microtcp_header_t))) < 0)
      {
        printf("Wrong check\n");
      }

      printf("sock seq = %ld\n", socket->seq_number);
      //header_recv.window += bytes_recv;
      //header_check.ack_number == header_recv.ack_number
      if ((socket->seq_number + (i + 1) * MICROTCP_MSS) != header_recv.ack_number || (erCh < 0)) //dupAck
      {
        //tempAck = header_recv.ack_number;
        tempSeq = header_recv.ack_number - MICROTCP_MSS;
        tempAck = header_recv.seq_number;

        printf("-----------------------\n");
        dupAcks++;

        printf("IN SEND: Received DUP ACK(Num of Dup Acks = %d)\n", dupAcks);
        if (dupAcks == 3)
        {
          printf("-----------------------\n");
          printf("RETRANSMISSION\n\n");
          socket->ssthresh = socket->cwnd / 2;
          socket->cwnd = socket->cwnd / 2 + 1;

          data_sent = data_sent_correctly;
          //tempSeq += data_sent;
          //tempAck = header_check.seq_number;
          dupAcks = 0;
          found3DA = 1;

          printf("Retransmitting packet with:\n\t Sequence = %d\n\t Acknowledge = %d\n\t Bytes Sent = %ld\n", tempSeq, tempAck, data_sent);

          break;
        }
        continue;
      }
      else
      {
        // header_check.ack_number = header_recv.ack_number;
        // header_check.seq_number = header_recv.seq_number;

        printf("IN SEND: Received correct ACK.\n\n");
        if (socket->cwnd <= socket->ssthresh) //slow start for every ACK
        {
          printf("ACK: In Slow Start..\n");
          socket->cwnd += MICROTCP_MSS;
        }
        else //congestion avoidance for every ACK
        {
          printf("ACK: In Congestion Avoidance..\n");
          socket->cwnd++;
        }

        data_sent_correctly += header_recv.data_len;
        printf("\t Control Window = %ld\n\t Ssthresh = %ld\n\t Data sent correctly = %ld\n", socket->cwnd, socket->ssthresh, data_sent_correctly);
      }

      socket->curr_win_size = header_recv.window;
      socket->ack_number = header_recv.ack_number;
      flow_ctrl_win = header_recv.window;
    }

    if (numOfAcks == numOfPackets)
    {
      printf("Packets sent are equal to Acks received!\n\n");

      if (socket->cwnd <= socket->ssthresh) //slow start for every RTT
      {
        printf("In Slow Start..\n");
        socket->cwnd = socket->cwnd * 2;
      }
      else //congestion avoidance for every RTT
      {
        printf("In Congestion Avoidance..\n");
        socket->cwnd += MICROTCP_MSS;
      }

      printf("\t Control Window = %ld\n\t Ssthresh = %ld\n", socket->cwnd, socket->ssthresh);
    }
    if (found3DA == 0)
    {

      remaining -= bytes_to_send;
      data_sent += bytes_to_send;
      // tempSeq+=bytes_to_send;
      socket->seq_number = tempSeq;
      //socket->ack_number = tempAck;

      printf("\nFinal socket->seq = %ld\n", socket->seq_number);
    }
    else
    {
      remaining -= data_sent_correctly;
      //socket->seq_number = header_check.ack_number;
      //socket->ack_number = header_check.seq_number;
      socket->seq_number = tempSeq;
      socket->ack_number = tempAck;
      //tempAck = socket->ack_number;

      printf("^^^^^^^^socket sequence number  that i will retrnasmit %d\n", socket->seq_number);

      //tempSeq = socket->seq_number;

      found3DA = 0;

      //crash = 3;

      printf("Final sent correctly sock seq = %d, ack = %d , renaining : %ld\n", tempSeq, tempAck, remaining);
    }
  }

  return data_sent;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  size_t bytes_recv = 0, data_recv = 0;
  char *buffer_rcvd = malloc((MICROTCP_MSS + sizeof(microtcp_header_t)) * sizeof(char));
  long int checksum0, checksum1;
  int countOfDA = 0;
  uint32_t check;

  microtcp_header_t header_recv;
  microtcp_header_t header_send;
  //socket->recvbuf = malloc(sizeof(uint8_t *) * MICROTCP_MSS);

  memset(&header_recv, 0, sizeof(microtcp_header_t));
  memset(&header_send, 0, sizeof(microtcp_header_t));
  //int len = sizeof(add_len);

  bytes_recv = recvfrom(socket->sd, buffer_rcvd, MICROTCP_MSS + sizeof(microtcp_header_t), flags, socket->dest_addr, &add_len);
  if ((int)bytes_recv < 0)
  {
    socket->state = INVALID;
    perror("ERROR IN RECEIVE: While receiving data.\n");
  }
  printf("-----------------------\n");
  printf("Receiving chunks..\n\n");

  data_recv = bytes_recv - sizeof(microtcp_header_t);
  printf("IN RECEIVE: %ld bytes received and data received : %ld\n", bytes_recv, data_recv);

  memcpy(&header_recv, buffer_rcvd, sizeof(microtcp_header_t));
  //check that recv buf has space for bytes_recv or make window =0
  if (socket->buf_fill_level + bytes_recv > MICROTCP_RECVBUF_LEN)
  {
    header_recv.window = 0;
  }
  else
  {
    memcpy(socket->recvbuf + socket->buf_fill_level, buffer_rcvd + sizeof(microtcp_header_t), data_recv);
    memcpy(buffer + socket->buf_fill_level, socket->recvbuf, data_recv);
    socket->buf_fill_level += data_recv;
  }

  header_recv = ntoh_func(header_recv);
  if (header_recv.control == 9)
  {
    printf("-----------------------\n");

    socket->seq_number = header_recv.seq_number;
    socket->ack_number = header_recv.ack_number;
    socket->control = header_recv.control;
    socket->state = CLOSING_BY_PEER;

    printf("1st recv server: seq_num %ld, ack_num %ld\nWith control %ld\n\n", socket->seq_number, socket->ack_number, socket->control);

    return 0;
  }

  printf("IN RECEIVE: Seq = %d, Ack = %d\n", header_recv.seq_number, header_recv.ack_number);

  checksum0 = (long int)header_recv.checksum;
  printf("Received in receive: checksum= %ld\n", checksum0);

  header_recv.checksum = 0;

  memcpy(buffer_rcvd, &header_recv, sizeof(microtcp_header_t));
  checksum1 = crc32((uint8_t *)buffer_rcvd, data_recv + sizeof(microtcp_header_t));
  printf("Computed in receive: checksum= %ld\n", checksum1);

  if (checksum0 != checksum1)
  {
    printf("IN RECEIVE: Not same checksum\n");
  }
  //crash++;
  crash = random_func();
  int x = 0;
  if ((crash * checksum0) % 2 == 1)
  {
    x = 1;
    printf("CRASH: x = %d\n", x);
    //header_recv.ack_number = socket->seq_number + 2;
  }
  else
  {

    printf("CRASH: x = %d\n", x);
  }

  printf("Header sequence %d , socket->ack %d\n", header_recv.seq_number, socket->ack_number);

  //x == 1 ||  in if for the retransmission
  if ((header_recv.seq_number != socket->ack_number) || (checksum0 != checksum1))
  {
    // while (1)
    // {
    //   if (countOfDA == 3)
    //     break;
    socket->state = DUP_ACK;
    printf("\n-----------------------\n");
    printf("Sending Duplicate ACK.\n");
    printf("-----------------------\n");

    header_send.control = my_modifyBit(header_send.control, 3, 1);
    header_send.control = my_modifyBit(header_send.control, 1, 0);
    header_send.ack_number = socket->ack_number;
    header_send.seq_number = socket->seq_number;
    checksum0 = crc32((uint8_t *)&header_send, sizeof(microtcp_header_t));
    header_send.checksum = checksum0;

    printf("Last correctly sent ack = %d, sock_ack = %ld\n", header_send.ack_number, socket->ack_number);

    header_send = hton_func(header_send);

    if ((microtcp_send_header(socket, &header_send, sizeof(microtcp_header_t), 0)) < 0)
    {
      socket->state = INVALID;
      perror("ERROR IN RECEIVE: While sending DUP ACK.\n");
    }
    // countOfDA++;
    // }
  }
  else
  {
    printf("-----------------------\n");
    printf("Sending ACK..\n\n");

    header_send.seq_number = header_recv.ack_number;
    header_send.ack_number = header_recv.seq_number + data_recv;
    header_send.window -= data_recv;
    header_send.control = my_modifyBit(header_send.control, 3, 1);
    header_send.control = my_modifyBit(header_send.control, 1, 0);
    header_send.data_len += data_recv;

    printf("header data length %d\n", header_send.data_len);
    printf("SEQ NUMBER = %d ACK NUMBER = %d, CONTROL NUMBER = %d\n", header_send.seq_number, header_send.ack_number, header_send.control);
    socket->seq_number = header_send.seq_number;
    socket->ack_number = header_send.ack_number;

    socket->curr_win_size = MICROTCP_RECVBUF_LEN - socket->buf_fill_level;
    printf("Socket seq = %ld, ack = %ld\n", socket->seq_number, socket->ack_number);

    header_send.checksum = 0;

    checksum0 = crc32((uint8_t *)&header_send, sizeof(microtcp_header_t));
    header_send.checksum = checksum0;
    printf("IN RECEIVE: Sending Checksum = %ld\n", (long int)header_send.checksum);

    header_send = hton_func(header_send);

    if ((microtcp_send_header(socket, &header_send, sizeof(microtcp_header_t), 0)) < 0)
    {
      socket->state = INVALID;
      perror("ERROR IN RECEIVE: While sending ACK.\n");
    }

    socket->buf_fill_level = 0;
    memset(&socket->recvbuf, 0, socket->buf_fill_level);

    return data_recv;
  }
}
