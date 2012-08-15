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

void ndp_spoof(const u_char *bytes, size_t len)
{
        size_t totlen = 0;
        struct ether_header *ether = NULL;
        struct ip6_hdr *ip = NULL;
        struct icmp6_hdr *icmp = NULL;
        char str_addr[INET6_ADDRSTRLEN];

        ether = (struct ether_header *)bytes;
        ip = (struct ip6_hdr *)(bytes + sizeof(struct ether_header));

        /* bzero(str_addr, INET6_ADDRSTRLEN); */
        /* inet_ntop(AF_INET6, &(ip->ip6_src), str_addr, INET6_ADDRSTRLEN); */
        /* debug("SRC IP6: %s", str_addr); */

        /* bzero(str_addr, INET6_ADDRSTRLEN); */
        /* inet_ntop(AF_INET6, &(ip->ip6_dst), str_addr, INET6_ADDRSTRLEN); */
        /* debug("DST IP6: %s", str_addr); */

        if (ip->ip6_nxt == IPPROTO_ICMPV6)
                icmp = (struct icmp6_hdr *)(bytes + sizeof(struct ether_header) 
                                            + sizeof(struct ip6_hdr));
        else
                warning("SKIP IPv6 EXTENSION HEADERS!!!");
        
        if (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                debug(">>>> INJECT!!!");
        }
}
