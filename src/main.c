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
        {NULL, 0, NULL, 0}
};

static const char *short_options = "hvi:";

pcap_t *pcap = NULL;
char *iface = NULL;

static int mitm = 0;

static void usage()
{
        printf("USAGE: mitm6 [OPTIONS] [ATTACK]\n");
        printf(" [OPTIONS]\n");
        printf("   -h, --help                  print this help\n");
        printf("   -v, --version               print version\n");
        printf("   -i, --iface <iface>         network interface\n");
        printf(" [ATTACK]\n");
        printf("   ndp-spoof\n");
        printf("   slaac [net-addr] [prefix]\n");
}

static void version()
{
        printf("\nMitm6 1.0\n");
        printf("Powered by Rocco 'LordZen' Folino\n");
        printf("Please send problems, bugs, questions, desirable enhancements, etc. to: lordzen@autistici.org\n\n");
}

static void signal_handler_cb(int signal)
{
        if (mitm == 1)
                stop_ndp_spoof();
        else
                stop_slaac();
}

int main(int argc, char **argv)
{
        int next_opt = 0;
        int opt_index = 0;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        
        /* Register signals */
        signal(SIGINT, &signal_handler_cb);
        signal(SIGTERM, &signal_handler_cb);

        /* Parse options */
        while ((next_opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1) {
                switch (next_opt) {
      
                case 'h':
                        usage();
                        return EXIT_SUCCESS;
      
                case 'v':
                        version();
                        return EXIT_SUCCESS;
      
                case 'i':
                        iface = (char *)optarg;
                        break;

                default:
                        usage();
                        return EXIT_FAILURE;
                        break;
                }
        }

        if (optind == argc) {
                usage();
                return EXIT_FAILURE;
        }

        /* Get iface name */
        if ((iface == NULL) && ((iface = pcap_lookupdev(errbuf)) == NULL)) {
                fatal(errbuf);
                exit(-1);
        }

        /* Open the device for capturing */
        pcap = pcap_open_live(iface, CAP_SNAPLEN, 1, -1, errbuf);
        if (pcap == NULL) {
                fatal(errbuf);
                exit(-1);
        }

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

        if (strncmp(argv[optind], "ndp-spoof", 9) == 0) {
                mitm = 1;
                start_ndp_spoof();
        } else if (strncmp(argv[optind], "slaac", 5) == 0) {
                mitm = 2;
                start_slaac();
        } else {
                pcap_freecode(&fp);
                pcap_close(pcap);
                usage();
                return EXIT_FAILURE;
        }

        pcap_freecode(&fp);
        pcap_close(pcap);
  
        debug("closed");

        return 0;
}
