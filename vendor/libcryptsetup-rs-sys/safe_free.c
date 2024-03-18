/*
 * utils_crypt - cipher utilities for cryptsetup
 *
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2019 Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#include "safe_free.h"

/*
 * Replacement for memset(s, 0, n) on stack that can be optimized out
 * Also used in safe allocations for explicit memory wipe.
 */
void crypt_memzero(void *s, size_t n)
{
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(s, n);
#else
	volatile uint8_t *p = (volatile uint8_t *)s;

	while(n--)
		*p++ = 0;
#endif
}

void crypt_safe_free(void *data)
{
	struct safe_allocation *alloc;

	if (!data)
		return;

	alloc = (struct safe_allocation *)
		((char *)data - offsetof(struct safe_allocation, data));

	crypt_memzero(data, alloc->size);

	alloc->size = 0x55aa55aa;
	free(alloc);
}
