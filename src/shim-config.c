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

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shim-config.h"
#include "atfork.h"


struct config_t {
    char *targetlib;
    char *logfilename;
    FILE *output;
    enum consistency_level_t consistency_level;
    pid_t pid;
    pid_t ppid;
};

static void shim_config_atexit_handler(void);

static struct config_t config = { 0 };	/* initialize to all zeroes */


void shim_config_set_output(bool forked)
{
    /* close file handle if previously open */
    if(config.output && config.output != stderr ) {
	shim_config_logfile_epilog(forked);
	free(config.logfilename);
	fclose(config.output);
    }

    config.output = stderr;	/* set it by default */
    config.logfilename = NULL;

    char *output = getenv("PKCS11SHIM_OUTPUT");
    if(output) {
	/* check if the PKCS11SHIM_OUTPUT contains %p */
	
	char *filename = NULL;
	char *lookup=strdup(output);
	
	if(!lookup) {
	    perror("Cannot duplicate string in memory");
	    goto error;
	}
	char *index=strstr(lookup, "%p"); /* we look for the first occurence of `%p` */

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

	/* carryon: */
	/* this section takes care of opening the file */
	if(filename) {
	    config.output = fopen(filename, "a");
	    if (!config.output) {
		perror("*** ERROR: could not open requested output file");
		config.output = stderr;
	    } else {
		config.logfilename = strdup(filename); /* keep a copy of the filename */
	    }
	    free(filename);
	}	
    }
}


inline void shim_config_set_pids()
{
    config.pid = getpid();
    config.ppid = getppid();
}

bool init_shim_config()
{
    char *targetlib = getenv("PKCS11SHIM");

    if(targetlib==NULL) {
	fprintf(stderr, "*** ERROR: no module specified. Please set PKCS11SHIM environment.\n");
	return false;
    }

    config.targetlib = strdup(targetlib);

    shim_config_set_output(false);	/* set output for config, based on PKCS11SHIM_OUTPUT content */

    /* by default, consistency_level is set to basic (0) */
    config.consistency_level = basic;

    /* set PID and PPID information */
    shim_config_set_pids();
    
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
	}
    }
    
    atfork_register_handlers();		/* register handlers to cope with threads after a fork */
    atexit(shim_config_atexit_handler); /* register exit handler */
    return true;
}


inline enum consistency_level_t shim_config_consistency_level() 
{
    return config.consistency_level;
}

inline bool shim_is_printing_deferred()
{
    return config.consistency_level == deferred;
}

inline FILE * shim_config_output()
{
    return config.output ? config.output : stderr;
}

inline pid_t shim_config_pid()
{
    return config.pid;
}

inline pid_t shim_config_ppid()
{
    return config.ppid;
}

inline const char * shim_config_library()
{
    return config.targetlib;
}   

static void shim_config_atexit_handler(void)
{
    if(config.targetlib) {
	free(config.targetlib);
	config.targetlib = NULL;
    }
    if(config.output && config.output != stderr) {
	shim_config_logfile_epilog(false);
	fclose(config.output);
	config.output = stderr;	/* back to default */
    }
    if(config.logfilename) {
	free(config.logfilename);
	config.logfilename = NULL;
    }
}



void shim_config_logfile_prolog(bool firsttime)
{
    fprintf(shim_config_output(), 
	    "\n\n"
	    "************************* PKCS#11 shim library *****************************\n"
	    "* - version %s%*s*\n"  
#if defined(HAVE_OPENSSL)
	    "* - with OpenSSL support                                                   *\n"
#else
	    "* - without OpenSSL support                                                *\n"
#endif
	    "* The following env variables can be used to adjust the library behaviour: *\n"
	    "* - PKCS11SHIM: contains the path of the library to intercept calls to     *\n"
	    "* - PKCS11SHIM_OUTPUT: path to an output file where to write logs          *\n"
	    "* - PKS11SHIM_CONSISTENCY: level of consistency for logs (0,1 or 2)        *\n"
	    "****************************************************************************\n"
	    "\n",
	    VERSION, (int)(63-strlen(VERSION)), "");

    if(firsttime) {
	fprintf(shim_config_output(), "pid: %d\nppid: unforked\n", getpid());
    } else {
	fprintf(shim_config_output(), "pid: %d\nppid: %d\n", getpid(), getppid());
    }

    fprintf(shim_config_output(), "PKCS11SHIM_LIBRARY=%s\n", config.targetlib);

    switch(shim_config_consistency_level()) {
    case per_callblock:		/* consistency per call accross threads, no deferred output */
	fprintf(shim_config_output(), "PKCS11SHIM_CONSISTENCY=1\n");
	fprintf(shim_config_output(), "*** WARNING: logging is serialized and grouped per API call, it may affect performance ***\n");
	break;
	
    case deferred:
	fprintf(shim_config_output(), "PKCS11SHIM_CONSISTENCY=2\n");
	fprintf(shim_config_output(), "*** WARNING: logging is deferred, log output is no more in sync with execution thread ***\n");
	fprintf(shim_config_output(), "*** WARNING: this mode may lead to memory overflow                                    ***\n");
	break;

    case basic:
    default:
	fprintf(shim_config_output(), "PKCS11SHIM_CONSISTENCY=0\n");
	fprintf(shim_config_output(), "*** WARNING: logging using basic mode, log entries may overlap for multithreaded applications ***\n");
	
    }

    fflush(shim_config_output());
}


inline void shim_config_logfile_epilog(bool forked)
{
    if(forked==true) {
	fprintf(shim_config_output(), "Process forked from %d to %d\n", getppid(), getpid());
    } else {
	fprintf(shim_config_output(), "*** EOF ***\n");
    }
}
