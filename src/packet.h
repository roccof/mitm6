/*
 * Copyright (c) Rocco Folino
 *
 * This file is part of mitm6.
 *
 * Mitm6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mitm6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mitm6.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef PACKET_H
#define PACKET_H

struct packet {
        int totlen;
        struct pkbuf *head;
        struct pkbuf *last;
};

struct pkbuf {
        struct packet *p;
        struct pkbuf *next;
        int type;
        u_char *data;
        int len;
};

#define PKB_T_ETH   0
#define PKB_T_IP6   1
#define PKB_T_ICMP6 2

struct packet *packet_init();
void packet_add_ether(struct packet *p, u_char *src, u_char *dst, uint16_t type);
void packet_add_ip6(struct packet *p, uint16_t plen, uint8_t nxt, uint8_t hlim, u_char *src, u_char *dst);
void packet_add_icmp6(struct packet *p, uint8_t type, uint8_t code, int cksum, u_char *data, int data_len);
void packet_add_icmp6_nd_na(struct packet *p, uint32_t flags, u_char *target);
void packet_free(struct packet *p);
int packet_send(char *iface, struct packet *p);

#endif /* PACKET_H */
