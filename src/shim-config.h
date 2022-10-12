/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2021 Mastercard
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

#if !defined(_SHIM_CONFIG_H_)
#define _SHIM_CONFIG_H_
/*
 * consistency_level_t: defines the desired consistency level
 *                      - basic:
 *                        Logs are directly written, from the same thread, to the output file.
 *                        Logs are therefore synchronous with the thread execution.
 *                        If several threads are running concurrently, log entries may overlap.
 *                        The basic mode is adequate for single-threaded executions.
 *
 *                      - per_callblock:
 *                        Logs are still written from the same thread as the caller,
 *                        but there is a mutex preventing log entries to overlap, within
 *                        one calling block. As a consequence, log entries will never
 *                        overlap for multithreaded executions.
 *                        However, it has a significant impact on performance.
 *                        Use this mode for logging on multithreaded executions, where impact
 *                        on performance is acceptable, or if you absolutely need to print
 *                        log entries synchronously with other output.
 *
 *                      - deferred:
 *                        Log entries are pushed to a queue. There is a queue worker that takes care
 *                        of emptying the queue, in a separate thread.
 *                        This mode provides good performance, and guarantees that no overlap may occur
 *                        accross threads. However it is memory-hungry, and log output is deferred,
 *                        which means you can't rely on the log entry to be printed in sync with other
 *                        output.
 *                        Use this mode for logging on multithreaded execution, where impact
 *                        on performance must be minimized, at the expense of memory consumption
 *                        and loss of synchronicity between logs and other output.
 *                        Beware: this mode may overflow memory, if writing to the output can't keep up
 *                        with the rate of incoming messages. You have been warned.
 *
 */

#include <stdio.h>
#include <stdbool.h>

enum consistency_level_t {
    basic,
    per_callblock,
    deferred
};

bool init_shim_config();
void shim_config_set_pids();
void shim_config_set_output(bool forked);
enum consistency_level_t shim_config_consistency_level();
bool shim_is_printing_deferred();
FILE * shim_config_output();
pid_t shim_config_pid();
pid_t shim_config_ppid();
const char * shim_config_library();
bool shim_config_canrevealpin();
void shim_config_logfile_prolog(bool firsttime);


#endif /* _SHIM_CONFIG_H_ */
