/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * pkcs11shim : a PKCS#11 shim library
 *
 * This work is based upon OpenSC pkcs11spy (https://github.com/OpenSC/OpenSC.git)
 *
 * Modified file Copyright (C) 2020  Mastercard
 * Original file Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

#if defined(__linux__)
/* bug in glibc: gettid() is not advertised
   https://stackoverflow.com/a/36025103/979318
*/
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

#if defined(__FreeBSD__) || defined(__AIX__)
#include <pthread_np.h>
#endif

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#define CRYPTOKI_EXPORTS
#include "pkcs11-display.h"
#include "libpkcs11.h"
#include "deferred-printf.h"
#include "shim-config.h"
#include "pkcs11-shim.h"

#define __PASTE(x, y) x##y

#define SPACER "      "

#if SIZE_MAX >= 18446744073709551615u
/* note: we could go up to 21 digits. */
#define CNTSTRING "\n[cnt] %016zu - %s\n"
#else
#define CNTSTRING "\n[cnt] %010u - %s\n"
#endif

/* Declare all shim_* Cryptoki function */

static void init_shim(void);

/* Shim Module Function List */
static CK_FUNCTION_LIST_PTR pkcs11_shim = NULL;
/* Real Module Function List */
static CK_FUNCTION_LIST_PTR po = NULL;
/* Dynamic Module Handle */
static void *modhandle = NULL;

/* global lock for printing */
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

/* flag to see if we use the lock */
static bool use_print_mutex = false;

/* once object for init_shim */
static pthread_once_t init_shim_invoked = PTHREAD_ONCE_INIT;

/* result of init_shim */
static CK_RV init_shim_rv = CKR_OK;

/* atomic counter (global to a process) */
static atomic_size_t cnt = 0;

/* utility : compute difference between two timevals */
/* x is always < y, and returned in result */
static void timeval_substract(struct timeval *result, struct timeval *x, struct timeval *y)
{
    result->tv_sec = y->tv_sec - x->tv_sec;
    result->tv_usec = y->tv_usec - x->tv_usec;

    if (result->tv_usec < 0)
    {
        result->tv_usec += 1000000;
        result->tv_sec -= 1;
    }
}

/* prelude */
static void enter(const char *function, struct timeval *tv)
{
    struct tm *tm;
    struct tm threadlocal_tm; /* used by localtime_r() */
    char time_string[40];

    /* atomically increase counter, and keep a copy of the value before increment */
    size_t callcnt = atomic_fetch_add_explicit(&cnt, 1, memory_order_relaxed);

    gettimeofday(tv, NULL);
    tm = localtime_r(&tv->tv_sec, &threadlocal_tm);
    strftime(time_string, sizeof(time_string), "%F %H:%M:%S", tm);

    if (use_print_mutex)
        pthread_mutex_lock(&print_mutex);

    deferred_fprintf(shim_config_output(), CNTSTRING, callcnt, function);
    deferred_fprintf(shim_config_output(), "[pid] %ld\n", shim_config_pid());
    deferred_fprintf(shim_config_output(), "[ppd] %ld\n", shim_config_ppid());
    deferred_fprintf(shim_config_output(), "[tid] %ld\n",
#if defined(__linux__)
                     gettid()
#elif defined(__FreeBSD__) || defined(__AIX__)
                     pthread_getthreadid_np()
#else
                     pthread_self()
#endif
	);
    deferred_fprintf(shim_config_output(), "[tic] %s.%06ld\n", time_string, (long)tv->tv_usec);
    /* we are just incrementing a counter, the relaxed memory model can be safely used */
}

/* postcall */
static CK_RV retne(CK_RV rv, struct timeval *prev_tv)
{
    struct tm *tm;
    struct timeval tv, elapsed;
    char time_string[40];
    struct tm threadlocal_tm; /* used by localtime_r() */

    gettimeofday(&tv, NULL);
    tm = localtime_r(&tv.tv_sec, &threadlocal_tm);
    strftime(time_string, sizeof(time_string), "%F %H:%M:%S", tm);
    deferred_fprintf(shim_config_output(), "[toc] %s.%06ld\n", time_string, (long)tv.tv_usec);
    timeval_substract(&elapsed, prev_tv, &tv);
    deferred_fprintf(shim_config_output(), "[lap] %ld.%06ld\n", (long)elapsed.tv_sec, (long)elapsed.tv_usec);
    deferred_fprintf(shim_config_output(), "[ret] %ld %s\n", (unsigned long)rv, lookup_enum(RV_T, rv));
    deferred_flush();
    if (use_print_mutex)
        pthread_mutex_unlock(&print_mutex);
    return rv;
}

static void shim_dump_string_in(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
    deferred_fprintf(shim_config_output(), "[in ] %s ", name);
    print_generic(shim_config_output(), 0, data, size, NULL);
}

static void shim_dump_sensitive_in(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
    deferred_fprintf(shim_config_output(), "[in ] %s ", name);
    if (shim_config_canrevealpin())
    {
        print_generic(shim_config_output(), 0, data, size, NULL);
    }
    else
    {
        print_sensitive(shim_config_output(), 0, data, size, NULL);
    }
}

static void shim_dump_string_out(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
    deferred_fprintf(shim_config_output(), "[out] %s ", name);
    print_generic(shim_config_output(), 0, data, size, NULL);
}

static void shim_dump_ulong_in(const char *name, CK_ULONG value)
{
    deferred_fprintf(shim_config_output(), "[in ] %s = 0x%lx\n", name, value);
}

static void shim_dump_ulong_out(const char *name, CK_ULONG value)
{
    deferred_fprintf(shim_config_output(), "[out] %s = 0x%lx\n", name, value);
}

static void _shim_dump_ptr(const char *name, const char *prefix, CK_VOID_PTR value)
{
    deferred_fprintf(shim_config_output(), "[%s] %s = %p\n", prefix, name, value);
    char *converted = value;
    if (converted && *converted)
    {
        // we make a bet here: if a value is provided to the pointer
        // we can at least print the length of the pointer itself.
        // beyond that we don't know if memory has been assigned.
        print_generic(shim_config_output(), 0, converted, sizeof (void *), NULL);
    }
}

static inline void shim_dump_ptr_in(const char *name, CK_VOID_PTR value)
{
    _shim_dump_ptr(name, "in", value);
}

static inline void shim_dump_ptr_out(const char *name, CK_VOID_PTR value)
{
    _shim_dump_ptr(name, "out", value);
}

static void shim_dump_desc_out(const char *name)
{
    deferred_fprintf(shim_config_output(), "[out] %s: \n", name);
}

static void shim_dump_array_out(const char *name, CK_ULONG size)
{
    deferred_fprintf(shim_config_output(), "[out] %s[%ld]: \n", name, size);
}

static void shim_attribute_req_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
                                  CK_ULONG ulCount)
{
    deferred_fprintf(shim_config_output(), "[in ] %s[%ld]: \n", name, ulCount);
    print_attribute_list_req(shim_config_output(), pTemplate, ulCount);
}

static void shim_attribute_list_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
                                   CK_ULONG ulCount)
{
    deferred_fprintf(shim_config_output(), "[in ] %s[%ld]: \n", name, ulCount);
    print_attribute_list(shim_config_output(), pTemplate, ulCount);
}

static void shim_attribute_list_out(const char *name, CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulCount)
{
    deferred_fprintf(shim_config_output(), "[out] %s[%ld]: \n", name, ulCount);
    print_attribute_list(shim_config_output(), pTemplate, ulCount);
}

static void print_ptr_in(const char *name, CK_VOID_PTR ptr)
{
    deferred_fprintf(shim_config_output(), "[in ] %s = %p\n", name, ptr);
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (po == NULL)
    {
        pthread_once(&init_shim_invoked, init_shim);
        CK_RV rv = init_shim_rv; /* take it from global */
        if (rv != CKR_OK)
            return rv;
    }

    struct timeval t;

    enter("C_GetFunctionList", &t);
    *ppFunctionList = pkcs11_shim;
    return retne(CKR_OK, &t);
}

CK_RV
shim_C_Initialize(CK_VOID_PTR pInitArgs)
{
    CK_RV rv;

    if (po == NULL)
    {
        pthread_once(&init_shim_invoked, init_shim);
        rv = init_shim_rv; /* take it from global */
        if (rv != CKR_OK)
            return rv;
    }

    struct timeval t;

    enter("C_Initialize", &t);
    print_ptr_in("pInitArgs", pInitArgs);

    if (pInitArgs)
    {
        CK_C_INITIALIZE_ARGS *ptr = pInitArgs;
        shim_dump_ulong_in("flags", ptr->flags);
	if (shim_config_preserved_is_a_string() && ptr->pReserved!=NULL) {
	    /* we assume that Preserved points to a string (NSS case) */
	    /* caution: this may lead to segfault, if the condition doesn't hold true! */
	    shim_dump_string_in("pReserved", ptr->pReserved, strlen(ptr->pReserved));
	} else {
	    shim_dump_ptr_in("pReserved", ptr->pReserved); /* we don't know, let's be cautious */
	}
        if (ptr->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
            deferred_fprintf(shim_config_output(), SPACER "CKF_LIBRARY_CANT_CREATE_OS_THREADS\n");
        if (ptr->flags & CKF_OS_LOCKING_OK)
            deferred_fprintf(shim_config_output(), SPACER "CKF_OS_LOCKING_OK\n");
    }

    rv = po->C_Initialize(pInitArgs);
    return retne(rv, &t);
}

CK_RV
shim_C_Finalize(CK_VOID_PTR pReserved)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Finalize", &t);
    rv = po->C_Finalize(pReserved);
    return retne(rv, &t);
}

CK_RV
shim_C_GetInfo(CK_INFO_PTR pInfo)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetInfo", &t);
    rv = po->C_GetInfo(pInfo);
    if (rv == CKR_OK)
    {
        shim_dump_desc_out("pInfo");
        print_ck_info(shim_config_output(), pInfo);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                   CK_ULONG_PTR pulCount)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetSlotList", &t);
    shim_dump_ulong_in("tokenPresent", tokenPresent);
    rv = po->C_GetSlotList(tokenPresent, pSlotList, pulCount);
    if (rv == CKR_OK)
    {
        shim_dump_desc_out("pSlotList");
        print_slot_list(shim_config_output(), pSlotList, *pulCount);
        shim_dump_ulong_out("*pulCount", *pulCount);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetSlotInfo", &t);
    shim_dump_ulong_in("slotID", slotID);
    rv = po->C_GetSlotInfo(slotID, pInfo);
    if (rv == CKR_OK)
    {
        shim_dump_desc_out("pInfo");
        print_slot_info(shim_config_output(), pInfo);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_GetTokenInfo(CK_SLOT_ID slotID,
                    CK_TOKEN_INFO_PTR pInfo)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetTokenInfo", &t);
    shim_dump_ulong_in("slotID", slotID);
    rv = po->C_GetTokenInfo(slotID, pInfo);
    if (rv == CKR_OK)
    {
        shim_dump_desc_out("pInfo");
        print_token_info(shim_config_output(), pInfo);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                        CK_ULONG_PTR pulCount)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetMechanismList", &t);
    shim_dump_ulong_in("slotID", slotID);
    rv = po->C_GetMechanismList(slotID, pMechanismList, pulCount);
    if (rv == CKR_OK)
    {
        shim_dump_array_out("pMechanismList", *pulCount);
        print_mech_list(shim_config_output(), pMechanismList, *pulCount);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                        CK_MECHANISM_INFO_PTR pInfo)
{
    CK_RV rv;
    const char *name = lookup_enum(MEC_T, type);
    struct timeval t;

    enter("C_GetMechanismInfo", &t);
    shim_dump_ulong_in("slotID", slotID);
    if (name)
        deferred_fprintf(shim_config_output(), SPACER "%30s \n", name);
    else
        deferred_fprintf(shim_config_output(), SPACER "Unknown Mechanism (%08lx)  \n", type);

    rv = po->C_GetMechanismInfo(slotID, type, pInfo);
    if (rv == CKR_OK)
    {
        shim_dump_desc_out("pInfo");
        print_mech_info(shim_config_output(), type, pInfo);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                 CK_UTF8CHAR_PTR pLabel)
{
    CK_RV rv;
    struct timeval t;

    enter("C_InitToken", &t);
    shim_dump_ulong_in("slotID", slotID);
    shim_dump_sensitive_in("pPin[ulPinLen]", pPin, ulPinLen);
    shim_dump_string_in("pLabel[32]", pLabel, 32);
    rv = po->C_InitToken(slotID, pPin, ulPinLen, pLabel);
    return retne(rv, &t);
}

CK_RV
shim_C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_InitPIN", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_sensitive_in("pPin[ulPinLen]", pPin, ulPinLen);
    rv = po->C_InitPIN(hSession, pPin, ulPinLen);
    return retne(rv, &t);
}

CK_RV
shim_C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
              CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SetPIN", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_sensitive_in("pOldPin[ulOldLen]", pOldPin, ulOldLen);
    shim_dump_sensitive_in("pNewPin[ulNewLen]", pNewPin, ulNewLen);
    rv = po->C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
    return retne(rv, &t);
}

CK_RV
shim_C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                   CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv;
    struct timeval t;

    enter("C_OpenSession", &t);
    shim_dump_ulong_in("slotID", slotID);
    shim_dump_ulong_in("flags", flags);
    deferred_fprintf(shim_config_output(), SPACER "pApplication=%p\n", pApplication);
    deferred_fprintf(shim_config_output(), SPACER "Notify=%p\n", (void *)Notify);
    rv = po->C_OpenSession(slotID, flags, pApplication, Notify, phSession);
    shim_dump_ulong_out("*phSession", *phSession);
    return retne(rv, &t);
}

CK_RV
shim_C_CloseSession(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    struct timeval t;

    enter("C_CloseSession", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_CloseSession(hSession);
    return retne(rv, &t);
}

CK_RV
shim_C_CloseAllSessions(CK_SLOT_ID slotID)
{
    CK_RV rv;
    struct timeval t;

    enter("C_CloseAllSessions", &t);
    shim_dump_ulong_in("slotID", slotID);
    rv = po->C_CloseAllSessions(slotID);
    return retne(rv, &t);
}

CK_RV
shim_C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetSessionInfo", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_GetSessionInfo(hSession, pInfo);
    if (rv == CKR_OK)
    {
        shim_dump_desc_out("pInfo");
        print_session_info(shim_config_output(), pInfo);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                         CK_ULONG_PTR pulOperationStateLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetOperationState", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_GetOperationState(hSession, pOperationState, pulOperationStateLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pOperationState[*pulOperationStateLen]", pOperationState, *pulOperationStateLen);
    return retne(rv, &t);
}

CK_RV
shim_C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
                         CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
    CK_RV rv;
    struct timeval t;

    enter("SetOperationState", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pOperationState[ulOperationStateLen]", pOperationState, ulOperationStateLen);
    shim_dump_ulong_in("hEncryptionKey", hEncryptionKey);
    shim_dump_ulong_in("hAuthenticationKey", hAuthenticationKey);
    rv = po->C_SetOperationState(hSession, pOperationState, ulOperationStateLen,
                                 hEncryptionKey, hAuthenticationKey);
    return retne(rv, &t);
}

CK_RV
shim_C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
             CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Login", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), "[in ] userType = %s\n",
                     lookup_enum(USR_T, userType));
    shim_dump_sensitive_in("pPin[ulPinLen]", pPin, ulPinLen);
    rv = po->C_Login(hSession, userType, pPin, ulPinLen);
    return retne(rv, &t);
}

CK_RV
shim_C_Logout(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Logout", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_Logout(hSession);
    return retne(rv, &t);
}

CK_RV
shim_C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phObject)
{
    CK_RV rv;
    struct timeval t;

    enter("C_CreateObject", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_attribute_list_in("pTemplate", pTemplate, ulCount);
    rv = po->C_CreateObject(hSession, pTemplate, ulCount, phObject);
    if (rv == CKR_OK)
        shim_dump_ulong_out("*phObject", *phObject);
    return retne(rv, &t);
}

CK_RV
shim_C_CopyObject(CK_SESSION_HANDLE hSession,
                  CK_OBJECT_HANDLE hObject,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulCount,
                  CK_OBJECT_HANDLE_PTR phNewObject)
{
    CK_RV rv;
    struct timeval t;

    enter("C_CopyObject", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("hObject", hObject);
    shim_attribute_list_in("pTemplate", pTemplate, ulCount);
    rv = po->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
    if (rv == CKR_OK)
        shim_dump_ulong_out("*phNewObject", *phNewObject);

    return retne(rv, &t);
}

CK_RV
shim_C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DestroyObject", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("hObject", hObject);
    rv = po->C_DestroyObject(hSession, hObject);
    return retne(rv, &t);
}

CK_RV
shim_C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetObjectSize", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("hObject", hObject);
    rv = po->C_GetObjectSize(hSession, hObject, pulSize);
    if (rv == CKR_OK)
        shim_dump_ulong_out("*pulSize", *pulSize);

    return retne(rv, &t);
}

CK_RV
shim_C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetAttributeValue", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("hObject", hObject);
    shim_attribute_req_in("pTemplate", pTemplate, ulCount);
    /* PKCS#11 says:
     * ``Note that the error codes CKR_ATTRIBUTE_SENSITIVE,
     *   CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL do not denote
     *   true errors for C_GetAttributeValue.''
     * That's why we ignore these error codes, because we want to display
     * all other attributes anyway (they may have been returned correctly)
     */
    rv = po->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
    if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
        rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_BUFFER_TOO_SMALL)
        shim_attribute_list_out("pTemplate", pTemplate, ulCount);
    return retne(rv, &t);
}

CK_RV
shim_C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SetAttributeValue", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("hObject", hObject);
    shim_attribute_list_in("pTemplate", pTemplate, ulCount);
    rv = po->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
    return retne(rv, &t);
}

CK_RV
shim_C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_RV rv;
    struct timeval t;

    enter("C_FindObjectsInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_attribute_list_in("pTemplate", pTemplate, ulCount);
    rv = po->C_FindObjectsInit(hSession, pTemplate, ulCount);
    return retne(rv, &t);
}

CK_RV
shim_C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                   CK_ULONG_PTR pulObjectCount)
{
    CK_RV rv;
    struct timeval t;

    enter("C_FindObjects", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("ulMaxObjectCount", ulMaxObjectCount);
    rv = po->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
    if (rv == CKR_OK)
    {
        CK_ULONG i;
        shim_dump_ulong_out("ulObjectCount", *pulObjectCount);
        for (i = 0; i < *pulObjectCount; i++)
            deferred_fprintf(shim_config_output(), SPACER "Object 0x%lx matches\n", phObject[i]);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    struct timeval t;

    enter("C_FindObjectsFinal", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_FindObjectsFinal(hSession);
    return retne(rv, &t);
}

CK_RV
shim_C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_EncryptInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    switch (pMechanism->mechanism)
    {
    case CKM_AES_GCM:
        if (pMechanism->pParameter != NULL)
        {
            CK_GCM_PARAMS *param =
                (CK_GCM_PARAMS *)pMechanism->pParameter;
            shim_dump_string_in("pIv[ulIvLen]",
                                param->pIv, param->ulIvLen);
            shim_dump_ulong_in("ulIvBits", param->ulIvBits);
            shim_dump_string_in("pAAD[ulAADLen]",
                                param->pAAD, param->ulAADLen);
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->ulTagBits=%lu\n", param->ulTagBits);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    case CKM_RSA_PKCS_OAEP:
        if (pMechanism->pParameter != NULL)
        {
            CK_RSA_PKCS_OAEP_PARAMS *param =
                (CK_RSA_PKCS_OAEP_PARAMS *)pMechanism->pParameter;
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->hashAlg=%s\n",
                             lookup_enum(MEC_T, param->hashAlg));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->mgf=%s\n",
                             lookup_enum(MGF_T, param->mgf));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->source=%s\n",
                             lookup_enum(CKZ_T, param->source));
            shim_dump_string_out("pSourceData[ulSourceDalaLen]",
                                 param->pSourceData, param->ulSourceDataLen);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    default:
        shim_dump_string_in("pParameter[ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
        break;
    }
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_EncryptInit(hSession, pMechanism, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Encrypt", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
    shim_dump_ulong_in("*pulEncryptedDataLen", *pulEncryptedDataLen);
    rv = po->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
    switch (rv)
    {
    case CKR_OK:
        shim_dump_string_out("pEncryptedData[*pulEncryptedDataLen]", pEncryptedData, *pulEncryptedDataLen);
        break;

    case CKR_BUFFER_TOO_SMALL:
        shim_dump_ulong_out("*pulEncryptedDataLen", *pulEncryptedDataLen);
        break;

    default:
        break;
    }
    return retne(rv, &t);
}

CK_RV
shim_C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                     CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_EncryptUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pPart, ulPartLen);
    shim_dump_ulong_out("*pulEncryptedDataLen", *pulEncryptedPartLen);
    rv = po->C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
    switch (rv)
    {
    case CKR_OK:
        shim_dump_string_out("pEncryptedData[*pulEncryptedDataLen]", pEncryptedPart, *pulEncryptedPartLen);
        break;

    case CKR_BUFFER_TOO_SMALL:
        shim_dump_ulong_out("*pulEncryptedDataLen", *pulEncryptedPartLen);
        break;

    default:
        break;
    }

    return retne(rv, &t);
}

CK_RV
shim_C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_EncryptFinal", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pLastEncryptedPart, *pulLastEncryptedPartLen);
    shim_dump_ulong_out("*pulLastEncryptedPartLen", *pulLastEncryptedPartLen);
    rv = po->C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
    switch (rv)
    {
    case CKR_OK:
        shim_dump_string_out("pLastEncryptedPart[*pulLastEncryptedPartLen]", pLastEncryptedPart, *pulLastEncryptedPartLen);
        break;

    case CKR_BUFFER_TOO_SMALL:
        shim_dump_ulong_out("*pulLastEncryptedPartLen", *pulLastEncryptedPartLen);
        break;

    default:
        break;
    }

    return retne(rv, &t);
}

CK_RV
shim_C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DecryptInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    switch (pMechanism->mechanism)
    {
    case CKM_AES_GCM:
        if (pMechanism->pParameter != NULL)
        {
            CK_GCM_PARAMS *param =
                (CK_GCM_PARAMS *)pMechanism->pParameter;
            shim_dump_string_in("pIv[ulIvLen]",
                                param->pIv, param->ulIvLen);
            shim_dump_ulong_in("ulIvBits", param->ulIvBits);
            shim_dump_string_in("pAAD[ulAADLen]",
                                param->pAAD, param->ulAADLen);
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->ulTagBits=%lu\n", param->ulTagBits);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    case CKM_RSA_PKCS_OAEP:
        if (pMechanism->pParameter != NULL)
        {
            CK_RSA_PKCS_OAEP_PARAMS *param =
                (CK_RSA_PKCS_OAEP_PARAMS *)pMechanism->pParameter;
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->hashAlg=%s\n",
                             lookup_enum(MEC_T, param->hashAlg));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->mgf=%s\n",
                             lookup_enum(MGF_T, param->mgf));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->source=%s\n",
                             lookup_enum(CKZ_T, param->source));
            shim_dump_string_out("pSourceData[ulSourceDalaLen]",
                                 param->pSourceData, param->ulSourceDataLen);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    default:
        shim_dump_string_in("pParameter[ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
        break;
    }
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_DecryptInit(hSession, pMechanism, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
               CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Decrypt", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pEncryptedData[ulEncryptedDataLen]", pEncryptedData, ulEncryptedDataLen);
    shim_dump_ulong_in("*pulDataLen", *pulDataLen);
    rv = po->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
    switch (rv)
    {
    case CKR_OK:
        shim_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
        break;

    case CKR_BUFFER_TOO_SMALL:
        shim_dump_ulong_out("*pulDataLen", *pulDataLen);
        break;

    default:
        break;
    }
    return retne(rv, &t);
}

CK_RV
shim_C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                     CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DecryptUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
    shim_dump_ulong_out("*pulPartLen", *pulPartLen);
    rv = po->C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
    switch (rv)
    {
    case CKR_OK:
        shim_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
        break;

    case CKR_BUFFER_TOO_SMALL:
        shim_dump_ulong_out("*pulPartLen", *pulPartLen);
        break;

    default:
        break;
    }

    return retne(rv, &t);
}

CK_RV
shim_C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DecryptFinal", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pLastPart[ulLastPartLen]", pLastPart, *pulLastPartLen);
    shim_dump_ulong_out("*pulLastPartLen", *pulLastPartLen);
    rv = po->C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
    switch (rv)
    {
    case CKR_OK:
        shim_dump_string_out("pLastPart[*pulLastPartLen]", pLastPart, *pulLastPartLen);
        break;

    case CKR_BUFFER_TOO_SMALL:
        shim_dump_ulong_out("*pulLastPartLen", *pulLastPartLen);
        break;

    default:
        break;
    }

    return retne(rv, &t);
}

CK_RV
shim_C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DigestInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    rv = po->C_DigestInit(hSession, pMechanism);
    return retne(rv, &t);
}

CK_RV
shim_C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
              CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Digest", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
    rv = po->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pDigest[*pulDigestLen]", pDigest, *pulDigestLen);

    return retne(rv, &t);
}

CK_RV
shim_C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DigestUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
    rv = po->C_DigestUpdate(hSession, pPart, ulPartLen);
    return retne(rv, &t);
}

CK_RV
shim_C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DigestKey", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_DigestKey(hSession, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DigestFinal", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_DigestFinal(hSession, pDigest, pulDigestLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pDigest[*pulDigestLen]", pDigest, *pulDigestLen);

    return retne(rv, &t);
}

CK_RV
shim_C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SignInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    shim_dump_string_in("pMechanism->pParameter[pMechanism->ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        if (pMechanism->pParameter != NULL)
        {
            CK_RSA_PKCS_PSS_PARAMS *param =
                (CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->hashAlg=%s\n",
                             lookup_enum(MEC_T, param->hashAlg));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->mgf=%s\n",
                             lookup_enum(MGF_T, param->mgf));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->sLen=%lu\n",
                             param->sLen);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    }
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_SignInit(hSession, pMechanism, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
            CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Sign", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
    rv = po->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);

    return retne(rv, &t);
}

CK_RV
shim_C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SignUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
    rv = po->C_SignUpdate(hSession, pPart, ulPartLen);
    return retne(rv, &t);
}

CK_RV
shim_C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SignFinal", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_SignFinal(hSession, pSignature, pulSignatureLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);

    return retne(rv, &t);
}

CK_RV
shim_C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SignRecoverInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n",
                     lookup_enum(MEC_T, pMechanism->mechanism));
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_SignRecoverInit(hSession, pMechanism, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SignRecover", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
    rv = po->C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);
    return retne(rv, &t);
}

CK_RV
shim_C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_VerifyInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    shim_dump_string_in("pMechanism->pParameter[pMechanism->ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
    switch (pMechanism->mechanism)
    {
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        if (pMechanism->pParameter != NULL)
        {
            CK_RSA_PKCS_PSS_PARAMS *param =
                (CK_RSA_PKCS_PSS_PARAMS *)pMechanism->pParameter;
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->hashAlg=%s\n",
                             lookup_enum(MEC_T, param->hashAlg));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->mgf=%s\n",
                             lookup_enum(MGF_T, param->mgf));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->sLen=%lu\n",
                             param->sLen);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    }
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_VerifyInit(hSession, pMechanism, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
              CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_Verify", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
    shim_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
    rv = po->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
    return retne(rv, &t);
}

CK_RV
shim_C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_VerifyUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
    rv = po->C_VerifyUpdate(hSession, pPart, ulPartLen);
    return retne(rv, &t);
}

CK_RV
shim_C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_VerifyFinal", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
    rv = po->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
    return retne(rv, &t);
}

CK_RV
shim_C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_VerifyRecoverInit", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_VerifyRecoverInit(hSession, pMechanism, hKey);
    return retne(rv, &t);
}

CK_RV
shim_C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                     CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_VerifyRecover", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
    rv = po->C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
    return retne(rv, &t);
}

CK_RV
shim_C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                           CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DigestEncryptUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
    rv = po->C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]", pEncryptedPart, *pulEncryptedPartLen);

    return retne(rv, &t);
}

CK_RV
shim_C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                           CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DecryptDigestUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
    rv = po->C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
    return retne(rv, &t);
}

CK_RV
shim_C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                         CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SignEncryptUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
    rv = po->C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]", pEncryptedPart, *pulEncryptedPartLen);

    return retne(rv, &t);
}

CK_RV
shim_C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                           CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DecryptVerifyUpdate", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
    rv = po->C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);

    return retne(rv, &t);
}

CK_RV
shim_C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GenerateKey", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    shim_attribute_list_in("pTemplate", pTemplate, ulCount);
    rv = po->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
    if (rv == CKR_OK)
        shim_dump_ulong_out("hKey", *phKey);

    return retne(rv, &t);
}

CK_RV
shim_C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                       CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                       CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                       CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GenerateKeyPair", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    shim_attribute_list_in("pPublicKeyTemplate", pPublicKeyTemplate, ulPublicKeyAttributeCount);
    shim_attribute_list_in("pPrivateKeyTemplate", pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
    rv = po->C_GenerateKeyPair(hSession, pMechanism,
                               pPublicKeyTemplate, ulPublicKeyAttributeCount,
                               pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                               phPublicKey, phPrivateKey);
    if (rv == CKR_OK)
    {
        shim_dump_ulong_out("hPublicKey", *phPublicKey);
        shim_dump_ulong_out("hPrivateKey", *phPrivateKey);
    }
    return retne(rv, &t);
}

CK_RV
shim_C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
               CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_WrapKey", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    switch (pMechanism->mechanism)
    {
    case CKM_AES_GCM:
        if (pMechanism->pParameter != NULL)
        {
            CK_GCM_PARAMS *param =
                (CK_GCM_PARAMS *)pMechanism->pParameter;
            shim_dump_string_in("pIv[ulIvLen]",
                                param->pIv, param->ulIvLen);
            shim_dump_ulong_in("ulIvBits", param->ulIvBits);
            shim_dump_string_in("pAAD[ulAADLen]",
                                param->pAAD, param->ulAADLen);
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->ulTagBits=%lu\n", param->ulTagBits);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    case CKM_RSA_PKCS_OAEP:
        if (pMechanism->pParameter != NULL)
        {
            CK_RSA_PKCS_OAEP_PARAMS *param =
                (CK_RSA_PKCS_OAEP_PARAMS *)pMechanism->pParameter;
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->hashAlg=%s\n",
                             lookup_enum(MEC_T, param->hashAlg));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->mgf=%s\n",
                             lookup_enum(MGF_T, param->mgf));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->source=%s\n",
                             lookup_enum(CKZ_T, param->source));
            shim_dump_string_out("pSourceData[ulSourceDalaLen]",
                                 param->pSourceData, param->ulSourceDataLen);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    default:
        shim_dump_string_in("pParameter[ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
        break;
    }
    shim_dump_ulong_in("hWrappingKey", hWrappingKey);
    shim_dump_ulong_in("hKey", hKey);
    rv = po->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
    if (rv == CKR_OK)
        shim_dump_string_out("pWrappedKey[*pulWrappedKeyLen]", pWrappedKey, *pulWrappedKeyLen);

    return retne(rv, &t);
}

CK_RV
shim_C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                 CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_UnwrapKey", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), SPACER "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
    switch (pMechanism->mechanism)
    {
    case CKM_AES_GCM:
        if (pMechanism->pParameter != NULL)
        {
            CK_GCM_PARAMS *param =
                (CK_GCM_PARAMS *)pMechanism->pParameter;
            shim_dump_string_in("pIv[ulIvLen]",
                                param->pIv, param->ulIvLen);
            shim_dump_ulong_in("ulIvBits", param->ulIvBits);
            shim_dump_string_in("pAAD[ulAADLen]",
                                param->pAAD, param->ulAADLen);
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->ulTagBits=%lu\n", param->ulTagBits);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    case CKM_RSA_PKCS_OAEP:
        if (pMechanism->pParameter != NULL)
        {
            CK_RSA_PKCS_OAEP_PARAMS *param =
                (CK_RSA_PKCS_OAEP_PARAMS *)pMechanism->pParameter;
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->hashAlg=%s\n",
                             lookup_enum(MEC_T, param->hashAlg));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->mgf=%s\n",
                             lookup_enum(MGF_T, param->mgf));
            deferred_fprintf(shim_config_output(), SPACER "pMechanism->pParameter->source=%s\n",
                             lookup_enum(CKZ_T, param->source));
            shim_dump_string_out("pSourceData[ulSourceDalaLen]",
                                 param->pSourceData, param->ulSourceDataLen);
        }
        else
        {
            deferred_fprintf(shim_config_output(), SPACER "Parameters block for %s is empty...\n",
                             lookup_enum(MEC_T, pMechanism->mechanism));
        }
        break;
    default:
        shim_dump_string_in("pParameter[ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
        break;
    }
    shim_dump_ulong_in("hUnwrappingKey", hUnwrappingKey);
    shim_dump_string_in("pWrappedKey[ulWrappedKeyLen]", pWrappedKey, ulWrappedKeyLen);
    shim_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
    rv = po->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate,
                         ulAttributeCount, phKey);
    if (rv == CKR_OK)
        shim_dump_ulong_out("hKey", *phKey);
    return retne(rv, &t);
}

CK_RV
shim_C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    struct timeval t;

    enter("C_DeriveKey", &t);
    shim_dump_ulong_in("hSession", hSession);
    deferred_fprintf(shim_config_output(), "[in ] pMechanism->type=%s\n",
                     lookup_enum(MEC_T, pMechanism->mechanism));
    switch (pMechanism->mechanism)
    {
    case CKM_ECDH1_DERIVE:
    case CKM_ECDH1_COFACTOR_DERIVE:
        if (pMechanism->pParameter == NULL)
        {
            deferred_fprintf(shim_config_output(), "[in ] pMechanism->pParameter = NULL\n");
            break;
        }
        CK_ECDH1_DERIVE_PARAMS *param =
            (CK_ECDH1_DERIVE_PARAMS *)pMechanism->pParameter;
        deferred_fprintf(shim_config_output(), "[in ] pMechanism->pParameter = {\n\tkdf=%s\n",
                         lookup_enum(CKD_T, param->kdf));
        deferred_fprintf(shim_config_output(), SPACER "\tpSharedData[ulSharedDataLen] = ");
        print_generic(shim_config_output(), 0, param->pSharedData,
                      param->ulSharedDataLen, NULL);
        deferred_fprintf(shim_config_output(), SPACER "\tpPublicData[ulPublicDataLen] = ");
        print_generic(shim_config_output(), 0, param->pPublicData,
                      param->ulPublicDataLen, NULL);
        deferred_fprintf(shim_config_output(), SPACER "}\n");
        break;
    case CKM_ECMQV_DERIVE:
        if (pMechanism->pParameter == NULL)
        {
            deferred_fprintf(shim_config_output(), "[in ] pMechanism->pParameter = NULL\n");
            break;
        }
        CK_ECMQV_DERIVE_PARAMS *param2 =
            (CK_ECMQV_DERIVE_PARAMS *)pMechanism->pParameter;
        deferred_fprintf(shim_config_output(), "[in ] pMechanism->pParameter = {\n\tkdf=%s\n",
                         lookup_enum(CKD_T, param2->kdf));
        deferred_fprintf(shim_config_output(), SPACER "\tpSharedData[ulSharedDataLen] =");
        print_generic(shim_config_output(), 0, param2->pSharedData,
                      param2->ulSharedDataLen, NULL);
        deferred_fprintf(shim_config_output(), SPACER "\tpPublicData[ulPublicDataLen] = ");
        print_generic(shim_config_output(), 0, param2->pPublicData,
                      param2->ulPublicDataLen, NULL);
        deferred_fprintf(shim_config_output(), SPACER "\tulPrivateDataLen = %lu",
                         param2->ulPrivateDataLen);
        deferred_fprintf(shim_config_output(), SPACER "\thPrivateData = %lu", param2->hPrivateData);
        deferred_fprintf(shim_config_output(), SPACER "\tpPublicData2[ulPublicDataLen2] = ");
        print_generic(shim_config_output(), 0, param2->pPublicData2,
                      param2->ulPublicDataLen2, NULL);
        deferred_fprintf(shim_config_output(), SPACER "\tpublicKey = %lu", param2->publicKey);
        deferred_fprintf(shim_config_output(), SPACER "}\n");
        break;
    }
    shim_dump_ulong_in("hBaseKey", hBaseKey);
    shim_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
    rv = po->C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
    if (rv == CKR_OK)
        shim_dump_ulong_out("hKey", *phKey);

    return retne(rv, &t);
}

CK_RV
shim_C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_SeedRandom", &t);
    shim_dump_ulong_in("hSession", hSession);
    shim_dump_string_in("pSeed[ulSeedLen]", pSeed, ulSeedLen);
    rv = po->C_SeedRandom(hSession, pSeed, ulSeedLen);
    return retne(rv, &t);
}

CK_RV
shim_C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GenerateRandom", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_GenerateRandom(hSession, RandomData, ulRandomLen);
    if (rv == CKR_OK)
        shim_dump_string_out("RandomData[ulRandomLen]", RandomData, ulRandomLen);
    return retne(rv, &t);
}

CK_RV
shim_C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    struct timeval t;

    enter("C_GetFunctionStatus", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_GetFunctionStatus(hSession);
    return retne(rv, &t);
}

CK_RV
shim_C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    CK_RV rv;
    struct timeval t;

    enter("C_CancelFunction", &t);
    shim_dump_ulong_in("hSession", hSession);
    rv = po->C_CancelFunction(hSession);
    return retne(rv, &t);
}

CK_RV
shim_C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
    CK_RV rv;
    struct timeval t;

    enter("C_WaitForSlotEvent", &t);
    shim_dump_ulong_in("flags", flags);
    if (pSlot != NULL)
    {
        shim_dump_ulong_in("pSlot", *pSlot);
    }
    rv = po->C_WaitForSlotEvent(flags, pSlot, pRserved);
    return retne(rv, &t);
}

/* Inits the shim. If successful, po != NULL */
static void init_shim(void)
{
    init_shim_rv = CKR_OK;

    /* Allocates and initializes the pkcs11_shim structure */
    pkcs11_shim = calloc(1, sizeof(CK_FUNCTION_LIST));
    if (pkcs11_shim)
    {
        /* with our own pkcs11.h we need to maintain this ourself */
        pkcs11_shim->version.major = 2;
        pkcs11_shim->version.minor = 11;
        pkcs11_shim->C_Initialize = shim_C_Initialize;
        pkcs11_shim->C_Finalize = shim_C_Finalize;
        pkcs11_shim->C_GetInfo = shim_C_GetInfo;
        pkcs11_shim->C_GetFunctionList = C_GetFunctionList;
        pkcs11_shim->C_GetSlotList = shim_C_GetSlotList;
        pkcs11_shim->C_GetSlotInfo = shim_C_GetSlotInfo;
        pkcs11_shim->C_GetTokenInfo = shim_C_GetTokenInfo;
        pkcs11_shim->C_GetMechanismList = shim_C_GetMechanismList;
        pkcs11_shim->C_GetMechanismInfo = shim_C_GetMechanismInfo;
        pkcs11_shim->C_InitToken = shim_C_InitToken;
        pkcs11_shim->C_InitPIN = shim_C_InitPIN;
        pkcs11_shim->C_SetPIN = shim_C_SetPIN;
        pkcs11_shim->C_OpenSession = shim_C_OpenSession;
        pkcs11_shim->C_CloseSession = shim_C_CloseSession;
        pkcs11_shim->C_CloseAllSessions = shim_C_CloseAllSessions;
        pkcs11_shim->C_GetSessionInfo = shim_C_GetSessionInfo;
        pkcs11_shim->C_GetOperationState = shim_C_GetOperationState;
        pkcs11_shim->C_SetOperationState = shim_C_SetOperationState;
        pkcs11_shim->C_Login = shim_C_Login;
        pkcs11_shim->C_Logout = shim_C_Logout;
        pkcs11_shim->C_CreateObject = shim_C_CreateObject;
        pkcs11_shim->C_CopyObject = shim_C_CopyObject;
        pkcs11_shim->C_DestroyObject = shim_C_DestroyObject;
        pkcs11_shim->C_GetObjectSize = shim_C_GetObjectSize;
        pkcs11_shim->C_GetAttributeValue = shim_C_GetAttributeValue;
        pkcs11_shim->C_SetAttributeValue = shim_C_SetAttributeValue;
        pkcs11_shim->C_FindObjectsInit = shim_C_FindObjectsInit;
        pkcs11_shim->C_FindObjects = shim_C_FindObjects;
        pkcs11_shim->C_FindObjectsFinal = shim_C_FindObjectsFinal;
        pkcs11_shim->C_EncryptInit = shim_C_EncryptInit;
        pkcs11_shim->C_Encrypt = shim_C_Encrypt;
        pkcs11_shim->C_EncryptUpdate = shim_C_EncryptUpdate;
        pkcs11_shim->C_EncryptFinal = shim_C_EncryptFinal;
        pkcs11_shim->C_DecryptInit = shim_C_DecryptInit;
        pkcs11_shim->C_Decrypt = shim_C_Decrypt;
        pkcs11_shim->C_DecryptUpdate = shim_C_DecryptUpdate;
        pkcs11_shim->C_DecryptFinal = shim_C_DecryptFinal;
        pkcs11_shim->C_DigestInit = shim_C_DigestInit;
        pkcs11_shim->C_Digest = shim_C_Digest;
        pkcs11_shim->C_DigestUpdate = shim_C_DigestUpdate;
        pkcs11_shim->C_DigestKey = shim_C_DigestKey;
        pkcs11_shim->C_DigestFinal = shim_C_DigestFinal;
        pkcs11_shim->C_SignInit = shim_C_SignInit;
        pkcs11_shim->C_Sign = shim_C_Sign;
        pkcs11_shim->C_SignUpdate = shim_C_SignUpdate;
        pkcs11_shim->C_SignFinal = shim_C_SignFinal;
        pkcs11_shim->C_SignRecoverInit = shim_C_SignRecoverInit;
        pkcs11_shim->C_SignRecover = shim_C_SignRecover;
        pkcs11_shim->C_VerifyInit = shim_C_VerifyInit;
        pkcs11_shim->C_Verify = shim_C_Verify;
        pkcs11_shim->C_VerifyUpdate = shim_C_VerifyUpdate;
        pkcs11_shim->C_VerifyFinal = shim_C_VerifyFinal;
        pkcs11_shim->C_VerifyRecoverInit = shim_C_VerifyRecoverInit;
        pkcs11_shim->C_VerifyRecover = shim_C_VerifyRecover;
        pkcs11_shim->C_DigestEncryptUpdate = shim_C_DigestEncryptUpdate;
        pkcs11_shim->C_DecryptDigestUpdate = shim_C_DecryptDigestUpdate;
        pkcs11_shim->C_SignEncryptUpdate = shim_C_SignEncryptUpdate;
        pkcs11_shim->C_DecryptVerifyUpdate = shim_C_DecryptVerifyUpdate;
        pkcs11_shim->C_GenerateKey = shim_C_GenerateKey;
        pkcs11_shim->C_GenerateKeyPair = shim_C_GenerateKeyPair;
        pkcs11_shim->C_WrapKey = shim_C_WrapKey;
        pkcs11_shim->C_UnwrapKey = shim_C_UnwrapKey;
        pkcs11_shim->C_DeriveKey = shim_C_DeriveKey;
        pkcs11_shim->C_SeedRandom = shim_C_SeedRandom;
        pkcs11_shim->C_GenerateRandom = shim_C_GenerateRandom;
        pkcs11_shim->C_GetFunctionStatus = shim_C_GetFunctionStatus;
        pkcs11_shim->C_CancelFunction = shim_C_CancelFunction;
        pkcs11_shim->C_WaitForSlotEvent = shim_C_WaitForSlotEvent;
    }
    else
    {
        init_shim_rv = CKR_HOST_MEMORY;
        return;
    }

    if (init_shim_config() == false)
    {
        init_shim_rv = CKR_GENERAL_ERROR;
        free(pkcs11_shim);
        return;
    }

    shim_config_logfile_prolog(true); /* print a banner */

    if (shim_config_consistency_level() == per_callblock)
    {
        use_print_mutex = true;
    }

    modhandle = C_LoadModule(shim_config_library(), &po);
    if (modhandle && po)
    {
        fprintf(shim_config_output(), "library: \"%s\"\n", shim_config_library());
    }
    else
    {
        po = NULL;
        free(pkcs11_shim);
        init_shim_rv = CKR_GENERAL_ERROR;
        return;
    }
}

inline void shim_lock_print(void)
{
    if (use_print_mutex)
        pthread_mutex_lock(&print_mutex);
}

inline void shim_unlock_print(void)
{
    if (use_print_mutex)
        pthread_mutex_unlock(&print_mutex);
}

inline void shim_reset_counter(void)
{
    cnt = 0;
}
