/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * pkcs11shim : a PKCS#11 shim library
 *
 * This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
 *
 * Copyright (C) 2020 Mastercard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#if !defined(_DEFERRED_PRINTF_H_)
#define _DEFERRED_PRINTF_H_

#include <threadqueue.h>

int deferred_fprintf(FILE *fp, const char * restrict fmt, ...);
void deferred_flush(void);
void deferred_atexit(void);
void deferred_lock_queue(void);
void deferred_unlock_queue(void);
void deferred_wait_until_empty();
void deferred_revive_thread(void);

#endif	/* _DEFERRED_PRINTF_H_ */
