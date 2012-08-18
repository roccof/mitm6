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

#include "mitm6.h"

/* uint16_t calculate_cksum(struct in6_addr *src, struct in6_addr *dst, uint8_t nxt_hdr, u_char *icmp, size_t icmp_len) */
/* { */
/*         return 0; */
/* } */

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
