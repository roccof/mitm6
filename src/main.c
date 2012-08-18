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
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>

#include "mitm6.h"

static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"iface", required_argument, NULL, 'i'},
        {"mitm", required_argument, NULL, 'M'},
        {"no-promisc", no_argument, NULL, 0},
        {"cap-timeout", required_argument, NULL, 0},
        {"cap-snaplen", required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
};

static pcap_t *pcap = NULL;
static int cap_snaplen = 65535;
static enum mitm mitm = NONE;
static const char *short_options = "hvi:m:";

static void usage()
{
        printf("USAGE: mitm6 [OPTIONS]\n");
        printf("  -h, --help                  print this help\n");
        printf("  -v, --version               print version\n");
        printf("  -i, --iface <iface>         network interface\n");
        printf("  -m, --mitm <method>         MiTM attack\n");
        printf("  --no-promisc                don't set iface in promisc mode\n");
        printf("  --cap-timeout               packet capture timeout, the default is 0 ms\n");
        printf("  --cap-snaplen               bytes of data of captured packet, the default is 65535 bytes\n");
}

static void version()
{
        printf("\nMitm6 1.0\n");
        printf("Powered by Rocco 'LordZen' Folino\n");
        printf("Please send problems, bugs, questions, desirable enhancements, etc. to: lordzen@autistici.org\n\n");
}

static void signal_handler_cb(int signal)
{
        /* TODO: check for multiples CTRL-C */
        pcap_breakloop(pcap);
}

static void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
        if (header->len == 0 || bytes == NULL)
                return;

        /* Skip truncated packets */
        if (header->len > cap_snaplen) {
                debug("captured truncated packet [pkt-len: %d, snaplen: %d], skipping...",
                      header->len, cap_snaplen);
                return;
        }
        
        switch(mitm) {
  
        case NDP_SPOOFING:
                debug("got packet of %d bytes", header->len);
                ndp_spoof(bytes, header->len);
                break;
  
        case NONE:
                warning("MiTM attack not selected");
        default:
                break;
        }
}

void inject_packet(u_char *bytes, size_t len)
{
        pcap_inject(pcap, (void *)bytes, len);
}

int main(int argc, char **argv)
{
        int next_opt = 0;
        int opt_index = 0;
        char *iface = NULL;
        int promisc = 1;
        int cap_timeout = 0;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;

        /* Register signals */
        signal(SIGINT, &signal_handler_cb);
        signal(SIGTERM, &signal_handler_cb);

        /* Parse options */
        while ((next_opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1) {
                switch (next_opt) {
                case 0:
                        if (strcmp(long_options[opt_index].name, "no-promisc") == 0) {
                                promisc = 0;
                        } else if (strcmp(long_options[opt_index].name, "cap-timeout") == 0) {
                                cap_timeout = atoi(optarg);
                        } else if (strcmp(long_options[opt_index].name, "cap-snaplen") == 0) {
                                cap_snaplen = atoi(optarg);
                        } else {
                                fatal("'%s' is an invalid option", long_options[opt_index].name);
                                usage();
                                return EXIT_FAILURE;
                        }
                        break;
      
                case 'h':
                        usage();
                        return EXIT_SUCCESS;
      
                case 'v':
                        version();
                        return EXIT_SUCCESS;
      
                case 'i':
                        iface = (char *)optarg;
                        break;

                case 'm':
                        switch(atoi((char *)optarg)) {
                        case 1:
                                debug("mitm attack: NDP Spoofing");
                                mitm = NDP_SPOOFING;
                                break;
                        case 2:
                                debug("mitm attack: SLAAC");
                                mitm = SLAAC_ATTACK;
                                break;
                        case 3:
                                debug("mitm attack: ICMPv6 Redirect");
                                mitm = ICMP6_REDIR;
                                break;
                        default:
                                fatal("invalid MiTM attack");
                                return EXIT_FAILURE;
                        }
                        break;

                default:
                        usage();
                        return EXIT_FAILURE;
                        break;
                }
        }

        if (mitm == NONE) {
                fatal("no MiTM attack specified");
                return EXIT_FAILURE;
        }

        /* Get iface name */
        if ((iface == NULL) && ((iface = pcap_lookupdev(errbuf)) == NULL)) {
                fatal(errbuf);
                exit(-1);
        }

        /* Open the device for capturing */
        pcap = pcap_open_live(iface, cap_snaplen, promisc, cap_timeout, errbuf);
        if (pcap == NULL) {
                fatal(errbuf);
                exit(-1);
        }

        /* TODO: enable */
        debug("enabled IPv6 forwarding");

        /* Sniff only ICMPv6 packets */
        if (pcap_compile(pcap, &fp, "icmp6", 0, PCAP_NETMASK_UNKNOWN) == -1) {
                fatal("couldn't parse filter: %s", pcap_geterr(pcap));
                pcap_close(pcap);
                return EXIT_FAILURE;
        }

        if (pcap_setfilter(pcap, &fp) == -1) {
                fatal("couldn't install filter %s", pcap_geterr(pcap));
                pcap_freecode(&fp);
                pcap_close(pcap);
                return EXIT_FAILURE;
        }
  
        /* Start sniffing */
        pcap_loop(pcap, 0, &process_packet, NULL);

        pcap_freecode(&fp);
        pcap_close(pcap);
  
        return 0;
}
