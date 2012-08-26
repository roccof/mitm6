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
#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#define ETH_TYPE_IP6 0x86dd

#define ETH_ADDR_LEN 6

struct ether {
        u_char dst[ETH_ADDR_LEN];
        u_char src[ETH_ADDR_LEN];
        uint16_t type;
};

#define IP6_ADDR_HOST   16
#define IP6_ADDR_LINK	32
#define IP6_ADDR_GLOBAL	 0

#define IP6_VERSION 0x60000000

#define IP6_HLIM 255

#define IP6_NXT_ICMP6 58

#define IP6_ADDR_LEN 16

struct ip6 {
        uint32_t vcf;
        uint16_t plen;
        uint8_t nxt;
        uint8_t hlim;
        u_char src[IP6_ADDR_LEN];
        u_char dst[IP6_ADDR_LEN];
};

#define ICMP6_T_ND_RS   133
#define ICMP6_T_ND_RA   134
#define ICMP6_T_ND_NS   135
#define ICMP6_T_ND_NA   136
#define ICMP6_T_REDIR   137

#define CALC_CKSUM 0xf1ca

struct icmp6 {
        uint8_t type;
        uint8_t code;
        uint16_t cksum;
};

struct icmp6_nd_ns {
        uint32_t reserved;
        u_char target[IP6_ADDR_LEN];        
};

#define ICMP6_ND_NA_F_ROUTER   0x80000000
#define ICMP6_ND_NA_F_SOLICIT  0x40000000
#define ICMP6_ND_NA_F_OVERRIDE 0x20000000

struct icmp6_nd_na {
        uint32_t flags;
        u_char target[IP6_ADDR_LEN];
};

#endif /* PROTOCOLS_H */
