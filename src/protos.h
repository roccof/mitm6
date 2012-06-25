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
#ifndef MITM6_PROTOS_H
#define MITM6_PROTOS_H

/*
 * Ethernet frame
 * ==============
 */

typedef struct _ethernet
{
  _uint8 dest_addr[ETHER_ADDR_LEN];   /* destination mac address */
  _uint8 src_addr[ETHER_ADDR_LEN];    /* source mac address */
  _uint16 type;                       /* packet type */
} ether_t;

#define	ETHER_TYPE_IPV6 0x86dd   /* IP protocol version 6 */

/*
 * RFC 2460 - IPv6 HEADER
 * ======================
 */

#define IPV6_ADDR_LEN 16 /* bytes */
#define IPV6_HDR_LEN 40  /* bytes */

typedef struct _ipv6 {
  _uint32 vtf;                     /* Version, Traffic Class, Flow Label */
  _uint16 plen;                    /* Payload length */
  _uint8 next_hdr;                 /* Next header */
  _uint8 hop_limit;                /* Hop limit */
  _uint8 src_addr[IPV6_ADDR_LEN];  /* Source address */
  _uint8 dst_addr[IPV6_ADDR_LEN];  /* Destination address */
} ipv6_t;

/* In host endian */
#define IPV6_VERSION(ip) ((ntohl((ip)->vtf) & 0xf0000000) >> 28)
#define IPV6_TRCLASS(ip) ((ntohl((ip)->vtf) & 0x0ff00000) >> 20)
#define IPV6_FLOW(ip)    (ntohl((ip)->vtf) & 0x000fffff)

#define IPV6_PROTO_ICMP 58

/* Extension headers */
#define IPV6_EXTH_HBH 0
#define IPV6_EXTH_DST_OPT 60
#define IPV6_EXTH_ROUTING 43
#define IPV6_EXTH_FRAG 44
#define IPV6_EXTH_AH 51
#define IPV6_EXTH_ESP 50
#define IPV6_NO_EXT_HDR 59

/*
 * RFC 2463, RFC 2461 - ICMPv6 HEADER
 * ==================================
 */

/* ICMPv6 general message */
typedef struct _icmp6 {
  _uint8 type;
  _uint8 code;
  _uint16 cksum;
} icmp6_t;

#define ICMP6_HDR_LEN sizeof(icmp6_t)

/* ICMPv6 echo body message */
typedef struct _icmp6_echo_body {
  _uint16 id;
  _uint16 seq;
} icmp6_echo_t;

/* ICMPv6 neighbor solicitation body message */
typedef struct _icmp6_neigh_sol {
  _uint32 reserved;
  _uint8 target_addr[IPV6_ADDR_LEN];
} icmp6_neigh_sol_t;

/* ICMPv6 neighbor advertisement body message */
typedef struct _icmp6_neigh_adv {
  _uint32 flags;
#define ICMP6_NEIGH_ADV_F_ROUTER 1 << 31
#define ICMP6_NEIGH_ADV_F_SOLICITED 1 << 30
#define ICMP6_NEIGH_ADV_F_OVERRIDE 1 << 29
  _uint8 target_addr[IPV6_ADDR_LEN];
} icmp6_neigh_adv_t;

/* ICMPv6 router advertisement body message */
typedef struct _icmp6_router_adv {
  _uint8 cur_hop_limit;
  _uint8 flags;
#define ICMP6_ROUTER_ADV_F_MANAGED 1 << 7
#define ICMP6_ROUTER_ADV_F_OTHER 1 << 6
  _uint16 router_lifetime;
  _uint32 reachable_time;
  _uint32 retrans_timer;
} icmp6_router_adv_t;

/* ICMPv6 type value  */
#define ICMP6_TYPE_DEST_UNREACH 1      /* Destination Unreachable */
#define ICMP6_TYPE_PKT_TOO_BIG 2       /* Packet Too Big */
#define ICMP6_TYPE_TIME_EXCEEDED 3     /* Time Exceeded */
#define ICMP6_TYPE_PARAM_PROB 4        /* Parameter Problem */
#define ICMP6_TYPE_ECHO_REQ 128        /* Echo Request */
#define ICMP6_TYPE_ECHO_REP 129        /* Echo Reply */
#define ICMP6_TYPE_ROUTER_SOL 133      /* ND Router Solicitation */
#define ICMP6_TYPE_ROUTER_ADV 134      /* ND Router Advertisement */
#define ICMP6_TYPE_NEIGH_SOL 135       /* ND Neighbor Solicitation */
#define ICMP6_TYPE_NEIGH_ADV 136       /* ND Neighbor Advertisement */
#define ICMP6_TYPE_REDIRECT 137        /* ND Redirect */
#define ICMP6_TYPE_ROUTER_RENUM 138    /* Router Renumbering */

/* ICMPv6 Destination Unreachable code value */
#define ICMP6_CODE_DEST_UNR_NO_ROUTE 0         /* No route to the destination */
#define ICMP6_CODE_DEST_UNR_COMMUN_ADM_PROIB 1 /* Communication Administratively
						  prohibited */
#define ICMP6_CODE_DEST_UNR_ADDR_UNREACH 3     /* Address unreachable */
#define ICMP6_CODE_DEST_UNR_PORT_UNREACH 4     /* Port unreachable */

/* ICMPv6 Time Exceeded code value */
#define ICMP6_CODE_TIME_EXC_HOP_LIM 0     /* Hop limit exceeded in transit */
#define ICMP6_CODE_TIME_EXC_FRAG_REASS 1  /* Fragment reassembly time exceeded */

/* ICMPv6 Parameter Problem code value */
#define ICMP6_CODE_PARAM_PROB_ERR_HDR_FIELD 0   /* Erroneous header field 
						   encountered */
#define ICMP6_CODE_PARAM_PROB_UNREC_NXT_HDR 1   /* Unrecognized Next Header 
						   type encountered */
#define ICMP6_CODE_PARAM_PROB_UNREC_OPT 2       /* Unrecognized IPv6 option 
						   encountered */

#endif /* MITM6_PROTOS_H */
