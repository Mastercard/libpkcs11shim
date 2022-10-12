/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * pkcs11shim : a PKCS#11 shim library
 *
 * This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
 *
 * Copyright (C) 2020  Mastercard
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

/* handlers for resetting threads & other mutexes after a fork */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include "deferred-printf.h"
#include "shim-config.h"
#include "pkcs11-shim.h"


static void shim_atfork_prepare(void)
{
    shim_lock_print();
    if(shim_is_printing_deferred()) {
	deferred_flush();	      /* flush the queue */
	deferred_wait_until_empty();  /* ensure the queue is empty */
	deferred_lock_queue();	      /* lock it */
    }
}

static void shim_atfork_parent(void)
{
    shim_unlock_print();
    if(shim_is_printing_deferred()) {
	deferred_unlock_queue();
    }
    /* we should be good from that point onwards */
}

static void shim_atfork_child(void)
{
    shim_reset_counter();	       /* new process, we reset the counter */
    shim_config_set_pids();            /* reset tracked PID and PPID */
    shim_config_set_output(true);      /* reset output file descriptor */
    shim_config_logfile_prolog(false); /* add banner */

    if(shim_is_printing_deferred()) {
	deferred_revive_thread();
	deferred_unlock_queue();
    }
    shim_unlock_print();	       /* release print */
}

void atfork_register_handlers()
{
    pthread_atfork(shim_atfork_prepare, shim_atfork_parent, shim_atfork_child);
}


/* EOF */
