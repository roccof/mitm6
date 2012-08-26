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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "mitm6.h"
#include "packet.h"

int get_iface_index(int sockfd, char *device)
{
  struct ifreq ifr;
  
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  
  if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
    return -1;
  
  return ifr.ifr_ifindex;
}

int get_mtu(char *iface)
{
        int s;
        struct ifreq ifr;
        
        if (iface == NULL)
                return -1;
                        
        if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
                return -1;

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
        
        if (ioctl(s, SIOCGIFMTU, (int8_t *) & ifr) < 0)
                return -1;
        
        close(s);
        debug("MTU: %d", ifr.ifr_mtu);
        
        return ifr.ifr_mtu;
}

u_char *get_mac(char *iface)
{
        int s;
        struct ifreq ifr;
        u_char *mac;
        
        if (iface == NULL)
                return NULL;
        
        if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
                return NULL;

        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
        if (ioctl(s, SIOCGIFHWADDR, (int8_t *) & ifr) < 0)
                return NULL;
        
        mac = (u_char *)malloc(6);
        memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6);
        close(s);
        
        debug("own MAC address: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        
        return mac;
}

void fatal(const char *message, ...)
{
        va_list ap;

        fprintf(stderr, "[!!] FATAL: ");

        va_start(ap, message);
        vfprintf(stderr, message, ap);
        va_end(ap);

        fprintf(stderr, "\n");
}

void debug(const char *message, ...)
{
#ifdef DEBUG

        va_list ap;

        fprintf(stderr, "[*] DEBUG: ");

        va_start(ap, message);
        vfprintf(stderr, message, ap);
        va_end(ap);

        fprintf(stderr, "\n");

#endif
}

void warning(const char *message, ...)
{
        va_list ap;

        fprintf(stderr, "[*] WARNING: ");

        va_start(ap, message);
        vfprintf(stderr, message, ap);
        va_end(ap);

        fprintf(stderr, "\n");
}