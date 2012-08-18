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
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "mitm6.h"
#include "packet.h"

#define PACKET_ADD(_packet, _data, _len)        \
        memcpy(_data, (_packet)->ptr, _len);    \
        (_packet)->len += _len;                 \
        (_packet)->ptr += _len;

struct packet *packet_init()
{
        struct packet *p = NULL;

        p = (struct packet *)malloc(sizeof(struct packet));
        if (p == NULL)
                return NULL;

        p->ptr = p->data;
        p->len = 0;

        return p;
}

void packet_add_ether(struct packet *p, u_char *src, u_char *dst, uint16_t type)
{
        struct ether_header ether;

        memcpy(src, ether.ether_shost, ETH_ALEN);
        memcpy(dst, ether.ether_dhost, ETH_ALEN);
        ether.ether_type = type;

        PACKET_ADD(p, &ether, sizeof(struct ether_header));
}

void packet_add_ip6(struct packet *p, uint16_t plen, uint8_t nxt, uint8_t hlim, struct in6_addr *src, struct in6_addr *dst, u_char *data)
{
        struct ip6_hdr ip;

        ip.ip6_flow &= 0xC0000000;
        ip.ip6_plen = plen;
        ip.ip6_nxt = nxt;
        ip.ip6_hlim = hlim;
        ip.ip6_src = *src;
        ip.ip6_dst = *dst;

        PACKET_ADD(p, &ip, sizeof(struct ip6_hdr));
        PACKET_ADD(p, data, plen);
}

void packet_add_icmp6(struct packet *p, uint8_t type, uint8_t code)
{
        
}

void packet_free(struct packet *p)
{
        if (p != NULL) {
                free(p);
                p = NULL;
        }
}
