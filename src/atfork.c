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
#include <stdbool.h>
#include "atfork.h"

#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
#include "deferred-printf.h"
#include "shim-config.h"
#include "pkcs11-shim.h"


static void shim_atfork_prepare(void)
{
    shim_lock_print();
    if(shim_is_printing_deferred()) {
        deferred_flush();             /* flush the queue */
        deferred_wait_until_empty();  /* ensure the queue is empty */
        deferred_lock_queue();        /* lock it */
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
    shim_reset_counter();              /* new process, we reset the counter */
    shim_config_set_pids();            /* reset tracked PID and PPID */
    shim_config_set_output(true);      /* reset output file descriptor */
    shim_config_logfile_prolog(false); /* add banner */

    if(shim_is_printing_deferred()) {
        deferred_revive_thread();
        deferred_unlock_queue();
    }
    shim_unlock_print();               /* release print */
}

void atfork_register_handlers()
{
    pthread_atfork(shim_atfork_prepare, shim_atfork_parent, shim_atfork_child);
}

#else /* _WIN32 */

/*
 * Native Windows has no fork(), so there is no atfork mechanism to register
 * and nothing for these handlers to repair. This is intentionally a no-op
 * rather than a missing feature.
 *
 * The POSIX handlers above exist solely to undo the side effects of fork():
 * fork() clones the parent's entire address space but keeps only the calling
 * thread, so inherited mutexes can be left locked with no surviving owner, the
 * deferred-printf worker thread is gone, and global state (call counter,
 * PID/PPID, open log handle) is a stale copy. The handlers quiesce/lock the
 * queue before the fork and, in the child, reset the counter, fix the
 * PID/PPID, reopen a per-PID log file, and recreate the worker thread.
 *
 * Windows creates new processes with CreateProcess(), which starts a fresh
 * process that does NOT inherit the parent's address space, threads, mutexes,
 * or open file handles. As a result none of the conditions above can occur:
 *   - no mutex can be inherited in a locked state with a missing owner;
 *   - no half-initialized deferred-printf worker thread is carried over;
 *   - the counter, PID/PPID and log handle are initialized fresh, not copied;
 *   - per-PID log separation (the "%p" expansion done by the fork child
 *     handler on POSIX) happens automatically because the child runs
 *     init_shim_config() from scratch with its own PID.
 *
 * Caveat: fork() emulation layers (e.g. Cygwin/MSYS2) copy the address space
 * and could reintroduce the POSIX hazards, but those runtimes are not targeted
 * by this (MinGW) build.
 */
void atfork_register_handlers()
{
    /* no-op on Windows: CreateProcess() inherits no state to recover */
}

#endif /* _WIN32 */


/* EOF */
