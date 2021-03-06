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
#ifndef MITM6_H
#define MITM6_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pcap.h>
#include <inttypes.h>

#define DEBUG

#define CAP_SNAPLEN 65535

void fatal(const char *message, ...);
void debug(const char *message, ...);
void warning(const char *message, ...);

int get_iface_index(int sockfd, char *device);
int get_mtu(char *iface);
u_char *get_mac(char *iface);

void start_ndp_spoof();
void stop_ndp_spoof();

void start_slaac();
void stop_slaac();

#endif /* MITM6_H */
