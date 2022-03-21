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
#include <unistd.h>
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

    config.output = stderr;	/* set it by default */
    char *output = getenv("PKCS11SHIM_OUTPUT");
    if(output) {

	/* check if the PKCS11SHIM_OUTPUT contains %p */
	
	char *filename = NULL;
	char *lookup=strdup(output);

	if(!lookup) {
	    perror("Cannot duplicate string in memory");
	    goto error;
	}
	char *index=strcasestr(lookup, "%p"); /* we look for the first occurence of `%p` */

	/* if found */
	if(index) {
	    size_t filename_size = strlen(output)+16; /* a printed PID should never exceed 16 chars */
	    filename=malloc(filename_size); 
	    if(!filename) {
		perror("Cannot allocate memory for generating filename");
		goto error;
	    }
	    
	    *index=0;		/* terminate the string there */

	    pid_t pid = getpid(); /* obtain PID */
	    snprintf(filename, filename_size, "%s%d%s", lookup, pid, index+2);

	} else {
	    filename = strdup(lookup);
	    if(!filename) {
		perror("Cannot allocate memory for generating filename");
		goto error;
	    }
	    
	}

    error:
	if(lookup) free(lookup);

	/* this section takes care of opening the file */
	if(filename) {
	    config.output = fopen(filename, "a");
	    if (!config.output) {
		perror("*** ERROR: could not open requested output file");
		config.output = stderr;
	    }
	    free(filename);
	}
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
