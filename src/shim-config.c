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

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "shim-config.h"
#include "atfork.h"


struct config_t {
    char *targetlib;
    char *logfilename;
    FILE *output;
    enum consistency_level_t consistency_level;
    pid_t pid;
    pid_t ppid;
    bool revealpin;
    bool preserved_is_a_string;
};

static void shim_config_atexit_handler(void);

static struct config_t config = { 0 };	/* initialize to all zeroes */


/* check if a file is regular                     */
/* i.e. it is not stderr, and the file descriptor */
/* points to a regular file (using S_ISREG macro) */

inline static bool is_file_regular(FILE *fp)
{
    bool rc = false;

    if(fp!=stderr) {
	struct stat sb;
	if(fstat(fileno(fp),&sb)==0 && S_ISREG(sb.st_mode)) {
	    rc = true;
	}
    }
    return rc;
}

/* if forked, print a message to log */
inline static void shim_config_logfile_forked(bool forked)
{
    if(forked) {
	fprintf(shim_config_output(), "[lib] process forked from %d to %d\n", getppid(), getpid());
    }
}


/* if called from non-forked process, add end of file indicator */
inline static void shim_config_logfile_epilog(bool forked)
{
    if(!forked) {
	fprintf(shim_config_output(), "[lib] *** EOF ***\n");
    }
}

/* This API is called in two circumstances;
 * - when the library starts
 * - after a fork
 * In the former case, we simply need to open the file.
 * In the later case, we must also detect what the current file handler is:
 * if it is pointing to a non-regular file,
 */
void shim_config_set_output(bool forked)
{
    /* if we forked, log it */
    shim_config_logfile_forked(forked);

    if(forked) {
	/* we must close file descriptors */
	/* only when it points to a real file */
	/* config.output is guaranteed to be initialized */
	if(is_file_regular(config.output)) {
	    shim_config_logfile_epilog(forked);
	    fclose(config.output);
	    config.output=stderr;
	} else {
	    /* fd points to a socket/symlink/device node */
	    /* don't do anything, keep it like that       */
	    return;
	}
    } else {
	/* at library init. just proceed as for a clean initialization */
	config.output=stderr;
    }

    /* in all the below, we are either from init of fork with a regular file */
    if(config.logfilename) {
	free(config.logfilename);
	config.logfilename = NULL;
    }

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
		perror("Cannot allocate memory, switching to stderr");
		goto error;
	    }

	    *index=0;		/* terminate the string there */

	    pid_t pid = getpid(); /* obtain PID */
	    snprintf(filename, filename_size, "%s%d%s", lookup, pid, index+2);
	} else {
	    /* no index found */
	    if(forked) {
		/* we have forked, but no %p can be found in the name */
		/* we simply suffix the filename with the pid         */

		/* a printed PID should never exceed 16 chars , + 1 char for '.' */
		size_t filename_size = strlen(output)+17;
		filename=malloc(filename_size);
		if(!filename) {
		    perror("Cannot allocate memory, switching to stderr");
		    goto error;
		}
		snprintf(filename, filename_size, "%s.%d", output, getpid());
	    } else {
		/* we haven't forked, use specified filename */
		filename = strdup(lookup);
		if(!filename) {
		    perror("Cannot allocate memory, switching to stderr");
		    goto error;
		}
	    }
	}

    error:
	if(lookup) free(lookup);

	/* carry_on: */
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

static void shim_config_set_pin_visibility()
{
    char *revealpin = getenv("PKCS11SHIM_REVEALPIN");
    if(revealpin && (
	   ( strcasecmp(revealpin,"1")==0 ) ||
	   ( strcasecmp(revealpin,"yes")==0 ) ||
	   ( strcasecmp(revealpin,"on")==0 ) ||
	   ( strcasecmp(revealpin,"true")==0 ))) {
	config.revealpin = true;
    } else {
	config.revealpin = false;
    }
}

/*
 *  PKCS11SHIM_PRESERVED_IS_A_STRING is useful only for NSS-like libraries
 *  when defined, it will try to interpret the pointer pReserved in C_CK_INITIALIZE_ARGS as
 *  a pointer to a configuration string.
 *
 */
static void shim_config_set_preserved_assumption() {
    char *preserved_assumption = getenv("PKCS11SHIM_PRESERVED_IS_A_STRING");
    if(preserved_assumption && (
	   ( strcasecmp(preserved_assumption,"1")==0 ) ||
	   ( strcasecmp(preserved_assumption,"yes")==0 ) ||
	   ( strcasecmp(preserved_assumption,"on")==0 ) ||
	   ( strcasecmp(preserved_assumption,"true")==0 ))) {
	config.preserved_is_a_string = true;
    } else {
	config.preserved_is_a_string = false;
    }
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

    /* set PIN visibility */
    shim_config_set_pin_visibility();

    /* set pReserved assumption */
    shim_config_set_preserved_assumption();

    /* set log output consistency level */
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


inline bool shim_config_canrevealpin()
{
    return config.revealpin;
}

inline bool shim_config_preserved_is_a_string()
{
    return config.preserved_is_a_string;
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
	fprintf(shim_config_output(), "*** WARNING: logging is synchronized with API call, it may affect performance         ***\n");
	break;

    case deferred:
	fprintf(shim_config_output(), "PKCS11SHIM_CONSISTENCY=2\n");
	fprintf(shim_config_output(), "*** WARNING: logging is deferred, log output is no more in sync with execution thread ***\n");
	fprintf(shim_config_output(), "*** WARNING: this mode may lead to memory exhaustion (on Linux, OOM kill may kick in) ***\n");
	break;

    case basic:
    default:
	fprintf(shim_config_output(), "PKCS11SHIM_CONSISTENCY=0\n");
	fprintf(shim_config_output(), "*** WARNING: logging using basic mode, log entries may overlap for multithreaded apps ***\n");

    }

    if(shim_config_canrevealpin()) {
	fprintf(shim_config_output(), "*** WARNING: PIN reveal mode enabled, log file may contain PINs or passphrases        ***\n");
    }

    if(shim_config_preserved_is_a_string()) {
	fprintf(shim_config_output(), "*** WARNING: PKCS11SHIM_PRESERVED_IS_A_STRING set, CK_C_INITIALIZE_ARGS is assumed    ***\n");
	fprintf(shim_config_output(), "*** WARNING: to point to a valid string. If that condition does not hold,             ***\n");
        fprintf(shim_config_output(), "*** WARNING: undefined behaviour may occur, and the application may crash             ***\n");
    }
	
    fflush(shim_config_output());
}
