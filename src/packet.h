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
        u_char data[65535];
        size_t len;
        u_char *ptr;
};

struct packet *packet_init();
void packet_add_ether(struct packet *p, u_char *src, u_char *dst, uint16_t type);
void packet_add_ip6(struct packet *p, uint16_t plen, uint8_t nxt, uint8_t hlim, struct in6_addr *src, struct in6_addr *dst, u_char *data);
void packet_add_icmp6(struct packet *p, uint8_t type, uint8_t code);
void packet_free(struct packet *p);

#endif /* PACKET_H */
