/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2021 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
