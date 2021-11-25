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
enum consistency_level_t shim_config_consistency_level();
FILE * shim_config_output();
const char * shim_config_library();


#endif /* _SHIM_CONFIG_H_ */
