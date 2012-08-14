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

#include "mitm6.h"
#include "protos.h"

static int is_icmp6_ns(const _uchar *bytes, size_t len)
{
  return 0;
}

void ndp_spoof(const _uchar *bytes, size_t len)
{
  size_t totlen = 0;
  ipv6_t *ip = NULL;
  icmp6_t *icmp = NULL;
  
  
}
