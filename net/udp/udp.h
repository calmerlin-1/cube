/** udp.h — minimal UDP socket layer for QUIC. */
#ifndef CUBE_UDP_H
#define CUBE_UDP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>


int udp_socket(int family);

int udp_connect(int fd, const char *ip, int family, uint16_t port,
                uint32_t timeout_ms);

int udp_send(int fd, const uint8_t *buf, size_t len,
             uint32_t timeout_ms);

ssize_t udp_recv(int fd, uint8_t *buf, size_t cap,
                 uint32_t timeout_ms);

void udp_close(int fd);

#endif
