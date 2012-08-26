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
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include <ctype.h>

#include "mitm6.h"
#include "packet.h"
#include "protocols.h"

extern pcap_t *pcap;

static void dump_data(unsigned char *buf, int len, char *text)
{
  unsigned char *p = (unsigned char *) buf;
  unsigned char lastrow_data[16];
  int rows = len / 16;
  int lastrow = len % 16;
  int i, j;

  if (buf == NULL || len == 0)
    return;

  if (text != NULL && text[0] != 0)
    printf("%s (%d bytes):\n", text, len);
  for (i = 0; i < rows; i++) {
    printf("%04hx:  ", i * 16);
    for (j = 0; j < 16; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    printf("   [ ");
    for (j = 0; j < 16; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    printf(" ]\n");
  }
  if (lastrow > 0) {
    memset(lastrow_data, 0, sizeof(lastrow_data));
    memcpy(lastrow_data, p + len - lastrow, lastrow);
    printf("%04hx:  ", i * 16);
    for (j = 0; j < lastrow; j++) {
      printf("%02x", p[(i * 16) + j]);
      if (j % 2 == 1)
        printf(" ");
    }
    while (j < 16) {
      printf("  ");
      if (j % 2 == 1)
        printf(" ");
      j++;
    }
    printf("   [ ");
    for (j = 0; j < lastrow; j++) {
      if (isprint(p[(i * 16) + j]))
        printf("%c", p[(i * 16) + j]);
      else
        printf(".");
    }
    while (j < 16) {
      printf(" ");
      j++;
    }
    printf(" ]\n");
  }
}

static uint16_t calculate_checksum(u_char *src, u_char *dst, uint8_t nxt, u_char *data, int len)
{
        u_char buf[40 + len];
        u_char *ptr = NULL;
        int checksum = 0;
        int i = 0;
        int buflen = 40 + len;
        
        if (buflen > 65535)
                warning("checksums hdr > 65535");
        
        bzero(&buf, buflen);

        memcpy(&buf[0], src, 16);
        memcpy(&buf[16], dst, 16);
        buf[34] = len / 256;
        buf[35] = len % 256;
        buf[39] = nxt;
        if (data != NULL && len > 0)
                memcpy(&buf[40], data, len);

#ifdef DEBUG
        dump_data(buf, buflen, "Cksum pseudo-header");
#endif

        /* Calculate checksum */
        ptr = buf;
        while (i < buflen) {
                if (i++ % 2 == 0)
                        checksum += *ptr++;
                else
                        checksum += *ptr++ << 8;
        }
        
        checksum = (checksum & 0xffff) + (checksum >> 16);
        checksum = htons(~checksum);

        debug("checksum: %d (0x%04x) = %p, %p, %d, %p, %d", checksum, checksum, src, dst, nxt, data, len);
        
        return checksum;
}


struct packet *packet_init()
{
        struct packet *p = NULL;

        p = (struct packet *)malloc(sizeof(struct packet));
        if (p == NULL)
                return NULL;

        p->totlen = 0;
        p->head = NULL;
        p->last = NULL;

        return p;
}

static void _add_pkbuf(struct packet *p, struct pkbuf *pkb)
{
        p->totlen += pkb->len;      

        if (p->head == NULL) {
                debug("append pkbuf [%d]", pkb->type);
                p->head = pkb;
                p->last = pkb;
        } else {
                debug("append pkbuf [%d --> %d]", p->last->type, pkb->type);
                struct pkbuf *last = p->last;
                last->next = pkb;
                p->last = pkb;
        }
}

static struct pkbuf *_find_pkbuf(struct packet *p, int type)
{
        struct pkbuf *pkb = NULL;
        
        for (pkb=p->head; pkb!=NULL; pkb=pkb->next) {
                if (pkb->type == type)
                        return pkb;
        }
        return NULL;
}

void packet_add_ether(struct packet *p, u_char *src, u_char *dst, uint16_t type)
{
        struct ether *e = NULL;
        struct pkbuf *pkb = NULL;

        if (p == NULL)
                return;

        pkb = (struct pkbuf *)malloc(sizeof(struct pkbuf));
        if (pkb == NULL)
                return;

        e = (struct ether *)malloc(sizeof(struct ether));
        if (e == NULL) {
                free(pkb);
                return;
        }

        memcpy(e->src, src, ETH_ADDR_LEN);
        memcpy(e->dst, dst, ETH_ADDR_LEN);
        e->type = type;

#ifdef DEBUG
        dump_data(e, sizeof(struct ether), "Ethernet header");
#endif

        pkb->p = p;
        pkb->type = PKB_T_ETH;
        pkb->len = sizeof(struct ether);
        pkb->data = (u_char *)e;
        pkb->next = NULL;

        _add_pkbuf(p, pkb);
}

void packet_add_ip6(struct packet *p, uint16_t plen, uint8_t nxt, uint8_t hlim, u_char *src, u_char *dst)
{
        struct ip6 *ip = NULL;
        struct pkbuf *pkb = NULL;

        if (p == NULL)
                return;

        pkb = (struct pkbuf *)malloc(sizeof(struct pkbuf));
        if (pkb == NULL)
                return;

        ip = (struct ip6 *)malloc(sizeof(struct ip6));
        if (ip == NULL) {
                free(pkb);
                return;
        }

        ip->vcf = htonl(IP6_VERSION);
        ip->plen = htons(plen);
        ip->nxt = nxt;
        ip->hlim = hlim;
        memcpy(ip->src, src, IP6_ADDR_LEN);
        memcpy(ip->dst, dst, IP6_ADDR_LEN);

#ifdef DEBUG
        dump_data(ip, sizeof(struct ip6), "IPv6 header");
#endif

        pkb->p = p;
        pkb->type = PKB_T_IP6;
        pkb->len = sizeof(struct ip6);
        pkb->data = (u_char *)ip;
        pkb->next = NULL;

        _add_pkbuf(p, pkb);
}

void packet_add_icmp6(struct packet *p, uint8_t type, uint8_t code, int cksum, u_char *data, int data_len)
{
        struct icmp6 icmp;
        struct pkbuf *pkb = NULL;
        u_char *buf = NULL;
        int totlen = 0;
        int do_cksum = 0;

        if (p == NULL)
                return;

        pkb = (struct pkbuf *)malloc(sizeof(struct pkbuf));
        if (pkb == NULL)
                return;

        totlen = sizeof(struct icmp6) + data_len;

        buf = (u_char *)malloc(totlen);
        if (buf == NULL) {
                free(pkb);
                return;
        }

        bzero(buf, totlen);

        icmp.type = type;
        icmp.code = code;
        if (cksum == CALC_CKSUM) {
                icmp.cksum = 0;
                do_cksum = 1;
        } else {
                icmp.cksum = cksum;
        }

        memcpy(buf, &icmp, sizeof(struct icmp6));
        memcpy((buf + sizeof(struct icmp6)), data, data_len);

        if (do_cksum) {
                /* struct icmp6 *icmp_p = (struct icmp6 *)buf; */
                struct pkbuf *pb = NULL;
                struct ip6 *ip = NULL;
                uint16_t c;

                /* Find IPv6 header */
                pb = _find_pkbuf(p, PKB_T_IP6);
                if (pb == NULL) {
                        fatal("no IPv6 header found, icmp6 hdr not added");
                        goto err;
                }

                ip = (struct ip6 *)pb->data;

                /* Udate IP6 packet len */
                ip->plen = htons(totlen);

                c = calculate_checksum(ip->src, ip->dst, ip->nxt, buf, totlen);

                /* Copy cksum */
                buf[2] = c / 256;
                buf[3] = c % 256;
        }

#ifdef DEBUG
        dump_data(buf, totlen, "ICMPv6 header");
#endif

        pkb->p = p;
        pkb->type = PKB_T_ICMP6;
        pkb->len = totlen;
        pkb->data = buf;
        pkb->next = NULL;

        _add_pkbuf(p, pkb);

        return;

 err:
        free(pkb);
        free(buf);
}

void packet_add_icmp6_nd_na(struct packet *p, uint32_t flags, u_char *target)
{
        struct ether *e = NULL;
        struct pkbuf *pkb = NULL;
        struct icmp6_nd_na na;
        u_char *buf = NULL;
        int totlen = 0;

        if (p == NULL)
                return;

        totlen = sizeof(struct icmp6_nd_na) + 8;

        buf = (u_char *)malloc(totlen);
        if (buf == NULL) {
                free(pkb);
                return;
        }

        bzero(buf, totlen);

        na.flags = htonl(flags);
        memcpy(na.target, target, IP6_ADDR_LEN);

        memcpy(buf, &na, sizeof(struct icmp6_nd_na));

        /* Find Ethernet header */
        pkb = _find_pkbuf(p, PKB_T_ETH);
        if (pkb == NULL) {
                fatal("no Ether header found, icmp6 nd na not added");
                goto err;
        }

        e = (struct ether *)pkb->data;
        
        /* Add Target Link-Layer Address Option */
        buf[sizeof(struct icmp6_nd_na) + 0] = 0x02;        /* Option type*/
        buf[sizeof(struct icmp6_nd_na) + 1] = 0x01;        /* Option len */
        buf[sizeof(struct icmp6_nd_na) + 2] = e->src[0];   /* Mac Address */
        buf[sizeof(struct icmp6_nd_na) + 3] = e->src[1];
        buf[sizeof(struct icmp6_nd_na) + 4] = e->src[2];
        buf[sizeof(struct icmp6_nd_na) + 5] = e->src[3];
        buf[sizeof(struct icmp6_nd_na) + 6] = e->src[4];
        buf[sizeof(struct icmp6_nd_na) + 7] = e->src[5];

        packet_add_icmp6(p, ICMP6_T_ND_NA, 0, CALC_CKSUM, buf, totlen);
 err:
        free(buf);
}

void packet_free(struct packet *p)
{
        struct pkbuf *pkb = NULL;
        void *ptrs[65535];
        int c = 0, i = 0;

        bzero(ptrs, 65535);

        for (pkb=p->head; pkb!=NULL; pkb=pkb->next) {
                ptrs[c++] = pkb->data;
                ptrs[c++] = pkb;
        }

        ptrs[c++] = p;

        for (i=0; i<c; i++)
                free(ptrs[i]);
}

static u_char *_packet2buf(struct packet *p, int *len)
{
        u_char *buf = NULL;
        u_char *ptr = NULL;
        struct pkbuf *pkb = NULL;

        buf = (u_char *)malloc(p->totlen);

        if (buf == NULL)
                return NULL;

        bzero(buf, p->totlen);
        ptr = buf;

        for (pkb=p->head; pkb!=NULL; pkb=pkb->next) {
                memcpy(ptr, pkb->data, pkb->len);
                ptr += pkb->len;
        }

        *len = p->totlen;

#ifdef DEBUG
        dump_data(buf, p->totlen, "Packet buffer");
#endif

        return buf;
}

int packet_send(char *iface, struct packet *p)
{
        int res = 0, len = 0, mtu = 0;
        u_char *buf = NULL;

        buf = _packet2buf(p, &len);
        if (buf == NULL) {
                fatal("invalid packet buffer");
                return -1;
        }

        mtu = get_mtu(iface);
        if (len > mtu)
                warning("packet size is larger than MTU of iface (%d > %d)", len, mtu);

        res = pcap_inject(pcap, buf, len);
        if (res == -1)
                fatal("packet not sent (%s)", pcap_geterr(pcap));
        else
                debug("sent packet (%d/%d bytes)", res, len);

#ifdef DEBUG
        dump_data(buf, len, "Sent packet");
#endif

        free(buf);

        return res;
}
