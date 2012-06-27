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

#define DEBUG

#define BITNO_32(_x) (((_x) >> 16) ? 16 + BITNO_16((_x) >> 16) : BITNO_16((_x)))
#define BITNO_16(_x) (((_x) >> 8) ? 8 + BITNO_8((_x) >> 8) : BITNO_8((_x)))
#define BITNO_8(_x) (((_x) >> 4) ? 4 + BITNO_4((_x) >> 4) : BITNO_4((_x)))
#define BITNO_4(_x) (((_x) >> 2) ? 2 + BITNO_2((_x) >> 2) : BITNO_2((_x)))
#define BITNO_2(_x) (((_x) & 2) ? 1 : 0)
#define BIT(_n)	(1 << _n)

typedef unsigned char _uint8;
typedef unsigned short _uint16;
typedef unsigned int _uint32;
typedef unsigned long _uint64;

typedef char _int8;
typedef short _int16;
typedef int _int32;
typedef long _int64;

typedef unsigned char _uchar;
typedef unsigned short _ushort;
typedef unsigned int _uint;
typedef unsigned long _ulong;

typedef enum _mitm_attacks {
  NDP_SPOOFING,
  SLAAC_ATTACK,
  ICMP6_REDIR,
  NONE
} mitm_t;

void fatal(const char *message, ...);
void debug(const char *message, ...);
void warning(const char *message, ...);

void inject_packet(_uchar *bytes, size_t len);

void ndp_spoof(const _uchar *bytes, size_t len);

#endif /* MITM6_H */
