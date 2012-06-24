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

int main(int argc, char **argv)
{
  int next_opt = 0;
  int opt_index = 0;
  char *iface = NULL;
  int no_promisc = 0;
  int cap_timeout = 0;
  int cap_snaplen = 65535;

  /* Parse options */
  while ((next_opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1) {
    switch (next_opt) {
    case 0:
      if (strcmp(long_options[opt_index].name, "no-promisc") == 0) {
      	no_promisc = 1;
      } else if (strcmp(long_options[opt_index].name, "cap-timeout") == 0) {
      	cap_timeout = atoi(optarg);
      } else if (strcmp(long_options[opt_index].name, "cap-snaplen") == 0) {
      	cap_snaplen = atoi(optarg);
      } else {
      	printf("ERROR: '%s' is an invalid option", long_options[opt_index].name);
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
      break;
	
    default:
      usage();
      return EXIT_FAILURE;
      break;
    }
  }

  /* TODO */

  return 0;
}