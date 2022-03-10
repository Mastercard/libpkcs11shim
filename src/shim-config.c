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

#include <stdlib.h>
#include <string.h>
#include "shim-config.h"


struct config_t {
    char *targetlib;
    FILE *output;
    enum consistency_level_t consistency_level;
};

static void shim_config_atexit_handler(void);

static struct config_t config = { 0 };	/* initialize to all zeroes */

bool init_shim_config()
{
    char *targetlib = getenv("PKCS11SHIM");

    if(targetlib==NULL) {
	fprintf(stderr, "*** ERROR: no module specified. Please set PKCS11SHIM environment.\n");
	return false;
    }

    config.targetlib = strdup(targetlib);

    char *output = getenv("PKCS11SHIM_OUTPUT");
    if(output) {
	config.output = fopen(output, "a");

	if (!config.output) {
	    perror("*** ERROR: could not open requested output file");
	    config.output = stderr;
	}
    } else {
	config.output = stderr;	/* by default: stderr */
    }

    char *consistency = getenv("PKCS11SHIM_CONSISTENCY");
    if(consistency) {
	enum consistency_level_t consistency_level = atoi(consistency);
	switch(consistency_level) {
	case basic:
	case per_callblock:
	case deferred:
	    config.consistency_level = consistency_level;
	    break;

	default:
	    fprintf(stderr,"*** WARNING: invalid consistency level specified: %u. Will use basic mode.\n", consistency_level);
	    config.consistency_level = basic;
	}
    }

    atexit(shim_config_atexit_handler); /* register exit handler */
    return true;
}


inline enum consistency_level_t shim_config_consistency_level() 
{
    return config.consistency_level;
}

inline FILE * shim_config_output()
{
    return config.output;
}

inline const char * shim_config_library()
{
    return config.targetlib;
}   

static void shim_config_atexit_handler(void)
{
    if(config.targetlib) { free(config.targetlib); config.targetlib = NULL; }
    if(config.output && config.output != stderr) { fclose(config.output); config.output = NULL; }
}
