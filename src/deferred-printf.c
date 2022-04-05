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

/* queue processor algorithm from https://stackoverflow.com/a/4577987/979318 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#endif
#include "threadqueue.h"
#include "shim-config.h"
#include "deferred-printf.h"

/* local types */
struct link_t {
    FILE *fp;
    char *buffer;
    struct link_t *next;
};

struct chain_t {
    struct link_t *top;
    struct link_t *last;
    size_t len;
};

enum message_t {
    new_message,
    ping,
    end_thread
};

/* prototypes */
static void * queue_processor(void *_ignore);
static void deferred_init_once(void);
int deferred_fprintf(FILE *fp, const char * restrict fmt, ...);
inline void deferred_flush(void);
static void deferred_destructor(void *ptr);
void deferred_atexit_handler(void);


/* static objects */
static pthread_key_t deferred_log_key;
static pthread_once_t deferred_log_once = PTHREAD_ONCE_INIT;
static int deferred_init_once_rv = 0;
static bool deferred_enabled = false;	      /* by default we are disabled */
static struct threadqueue deferred_log_queue; /* our queue */
static pthread_t queue_processor_thread;



/* this function prints what's in the queue */
static void * queue_processor(void *_ignore)
{
    int rc;
    struct threadmsg msg;
    bool carry_on=true;

    while(carry_on==true) {
	rc = thread_queue_get(&deferred_log_queue,NULL,&msg);

	switch((enum message_t)msg.msgtype){
	case new_message:
	{
	    struct chain_t *chain = msg.data;
	    struct link_t *link;

	    for(link=chain->top; link;) {
		fputs(link->buffer, link->fp);    /* the real fprintf() is happening here */
		fflush(link->fp);                 /* flush out */
		free(link->buffer);
		struct link_t *next = link->next; /* remember next link before freeing */
		free(link);			  /* free link */
		link=next;			  /* point to the next */
	    }
	    free(chain);	/* free the chain structure */
	}
	break;

	case ping:
	    break;
	       
	case end_thread:
	default:
	    carry_on = false;
	}
    }
    return NULL;
}

static void deferred_init_once(void)
{
    if(shim_config_consistency_level()==deferred)
    {
	deferred_enabled = true;
	pthread_key_create(&deferred_log_key, deferred_destructor);
	deferred_init_once_rv = thread_queue_init(&deferred_log_queue); /* create the queue */
    
	if(deferred_init_once_rv==0) {
	    pthread_create(&queue_processor_thread, NULL, queue_processor, NULL); /* create the worker thread */
	    atexit(deferred_atexit_handler);
	}
    } else {
	deferred_enabled = false;
    }
}


int deferred_fprintf(FILE *fp, const char * restrict fmt, ...)
{
    int rc = -1;
    
    pthread_once(&deferred_log_once, deferred_init_once); /* initialize key */
    if (deferred_init_once_rv != 0) {
	fprintf(stderr, "***ERROR could not initialize deferred print subsystem, using same thread logging facility ***\n");
	deferred_enabled = false;
    }

    va_list args;
    char *buffer;
    int n;

    if(deferred_enabled == true && deferred_init_once_rv == 0) {
	va_start (args, fmt);
	n = vsnprintf(buffer,0,fmt,args); /* estimate requested length to allocate buffer */
	va_end (args);

	buffer = malloc(n+1);
	if(buffer == NULL) goto cleanup;

	va_start (args, fmt);
	rc = vsnprintf(buffer,n+1,fmt,args);   /* print stuff, really */
	va_end (args);

	if(rc<0) goto cleanup;

	struct link_t *link;
	link = calloc(1,sizeof(struct link_t));
	if(link==NULL) goto cleanup;

	struct chain_t *chain; 
	if((chain=pthread_getspecific(deferred_log_key))==NULL) { /* create the structure */
	    chain = calloc(1, sizeof(struct chain_t));
	    if(chain==NULL) goto cleanup;

	    chain->last = chain->top = link;	/* we can setup the environment */
	    chain->len++;
	    pthread_setspecific(deferred_log_key, chain); /* set the local storage */
	} else {
	    /* the key already exists, just update it */
	    chain->last->next = link;
	    chain->last = link;
	    chain->len++;
	}

	link->fp = fp;
	link->buffer = buffer; buffer = NULL;
	link->next = NULL;

	/* link has been already assigned to chain, so forget it */
	link = NULL;

    cleanup:
	if(buffer) free(buffer);
	if(link) free(link);
    } else {
	/* PKCS11SHIM_SYNCHRONOUS requested, we print directly */
	va_start (args, fmt);
	n = vfprintf(fp,fmt,args); 
	va_end (args);
    }
    return rc;
}


inline void deferred_flush(void)
{
    struct chain_t *chain; 

    if (deferred_init_once_rv==0 && deferred_enabled==true) {

	chain=pthread_getspecific(deferred_log_key);
	if(chain) {
	    thread_queue_add(&deferred_log_queue, chain, new_message);
	    /* we passed the whole chain of stuff to print */
	    /* now we can simply "forget" the chain structure */
	    /* the worker thread will take care of freeing the links and chain */
	    pthread_setspecific(deferred_log_key, NULL);
	}
    }
}


static void deferred_destructor(void *ptr)
{
    struct chain_t *chain = ptr;
    /* flush the content */
    if (deferred_init_once_rv==0 && deferred_enabled==true) {
	thread_queue_add(&deferred_log_queue, chain, end_thread);
    }
}

void deferred_atexit_handler(void)
{
    if (deferred_init_once_rv==0 && deferred_enabled==true) {
	thread_queue_add(&deferred_log_queue,NULL, end_thread); /* inform the working thread it's over */
	pthread_join(queue_processor_thread, NULL);
    }
}

inline void deferred_lock_queue(void)
{
    thread_queue_lock(&deferred_log_queue);
}

inline void deferred_unlock_queue(void)
{
    thread_queue_unlock(&deferred_log_queue);
}

inline void deferred_wait_until_empty()
{
    while(thread_queue_length(&deferred_log_queue)>0) {
#ifdef __linux__
	sched_yield();
#else
	pthread_yield();
#endif
    }
}

void deferred_revive_thread(void)
{
    /* we are right after a fork */

    if(deferred_init_once_rv==0 && deferred_enabled==true) {

        /* first cleanup deferred_log_queue. We can as no other thread is accessing this */
	thread_queue_cleanup(&deferred_log_queue, 1);

	/* second: any key-speficic data is rendered invalid - since calling thread is different */
	/* we have ensured in the calling process that the queue was emptied                     */
	pthread_key_create(&deferred_log_key, deferred_destructor);

	/* third: restart the thread */
	deferred_init_once_rv = thread_queue_init(&deferred_log_queue); /* create the queue */

	if(deferred_init_once_rv==0) {
	    pthread_create(&queue_processor_thread, NULL, queue_processor, NULL); /* create the worker thread */
	    /* atexit(deferred_atexit_handler);  */
	}
    }
    
}
/* EOF */
