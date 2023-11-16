# libpkcs11shim : a shim library for PKCS#11

## Introduction
`libpkcs11shim` is a shim library that you insert between an application and a target PKCS#11 library. This project is actually a fork on a small part of [OpenSC project on GitHub](https://github.com/OpenSC/OpenSC), called [`pkcs11-spy`](src/pkcs11/pkcs11-spy.c). In addition to `pkcs11-spy`, `libpkcs11shim` adds some capabilities:
 - cleaner log output
 - ability to capture logs in a multithreaded environment
 - ability to carry on capture upon fork of the calling process
 - provides a deferred logging capability, reducing significantly the impact on performance on a library being logged (at the cost of extra memory allocation)
 - microsecond resolution for API call, allowing to identify library performance problems
 - hides passphrase information by default (that can be overriden by an environment variable, see options below)

## Download
Releases are hosted on Github: https://github.com/Mastercard/libpkcs11shim/releases/

## Usage
To use this library:
- define `PKCS11SHIM` environment variable to contain the original PKCS#11 library full path;
- in your application, set the path to the `libpkcs11shim.so` library as the PKCS#11 library to use;
- run your program as usual.

### options
The following environment variables can be defined, to adjust logging behaviour:

- `PKCS11SHIM_OUTPUT`, when present, specifies a filename where the log entries should be written. Fi the file already exists, logs will be appended to it. If the filename contains `%p`, it will be replaced with the pid of the running process. When `PKCS11SHIM_OUTPUT` is not specified, output goes to `/dev/stderr`.
- `PKCS11SHIM_CONSISTENCY`; when present, allows to adjust how consistent are logs, in a multithreaded environment:

	- `0` (basic)
	  Logs are directly written, from the same thread, to the output file. Logs are therefore **synchronous** with the thread execution. If several threads are running concurrently, log entries may overlap. The basic mode is **adequate for single-threaded executions**.
	- `1` (consistent callblocks)
	  Logs are still written from the same thread as the caller, but there is a mutex preventing log entries to overlap, within one calling block. As a consequence, log entries will never overlap for multithreaded executions. However, it has a **significant impact on performance**. **Use this mode for logging on multithreaded executions, where impact on performance is acceptable**, or if you absolutely need to print log entries synchronously with other output.
	- `2` (deferred)
	  Log entries are pushed to a queue. There is a queue worker that takes care of emptying the queue, in a separate thread. **This mode provides good performance, and guarantees that, in log output, no overlap may occur accross threads**. However it is memory-hungry, and log output is deferred, which means you can't rely on the log entry to be printed in sync with other output. Use this mode for logging on multithreaded execution, where impact on performance must be minimized, at the expense of memory consumption and loss of synchronicity between logs and other output.
	  Beware: **this mode may overflow memory, if writing to the output can't keep up with the rate of incoming messages**. You have been warned!

- `PKCS11SHIM_REVEALPIN`, when present and set to `1`, `on`, `yes` or `true`, will reveal the PIN or passphrase passed to the `C_Login()` API call.

## Building

To build the library:
 1. clone the repo from GitHub
 2. From the repo directory, execute `./bootstrap.sh`
 3. execute `./configure`. As usual, configure script contains several options that can be useful to better match your environment.
 4. execute `make`
 5. optionally, `make install`. The library is named `libpkcs11shim.so` and is deployed by default to `/usr/local/lib`.

## Output format

### Fields description

- `[cnt]`: a unique counter that is monolithically and atomically increased for every use, followed by the API being invoked.
- `[pid]`: process ID of the calling process
- `[ppd]`: parent process ID of the calling process. This can be helpful when the application uses `fork()`; in which case, each process results in the creation of a separate log file.
- `[tid]`: thread ID (platform-specific)
- `[tic]`: timestamp when the PKCS\#11 function is invoked (resolution: microsecond)
- `[in ]`: input parameters to the API call. Please refer to the PKCS#11 standard for a description of the fields.
- `[out]`: output parameters of the API call. Please refer to the PKCS#11 standard for a description of the fields.
- `[toc]`: timestamp when the API call is returned (resolution: microsecond)
- `[lap]`: elapsed time, in microseconds (i.e., `[toc] - [tic]`)
- `[ret]`: the return code of the API call.

### Samples
Every log entry looks like the following:
```
[cnt] 0000000000000020 - C_GetAttributeValue
[pid] 230885
[ppd] 230878
[tid] 230885
[tic] 2023-06-28 16:32:50.903681
[in ] hSession = 0x8cb
[in ] hObject = 0x470
[in ] pTemplate[1]: 
      CKA_CLASS             0000000000000000 / 0
[out] pTemplate[1]: 
      CKA_CLASS             0000000000000000 / 8
[toc] 2023-06-28 16:32:50.903695
[lap] 0.000014
[ret] 0 CKR_OK
```

Depending on the content, `[in ]` and `[out]` may be enriched with additional information. In the following sample, one can see that for every template entry, `type` is displayed, as well as `ulValueLen` and `pLen`; in the response received, the value `-1` for `ulValueLen` is interpreted as `CK_UNAVALABLE_INFORMATION`.

```
[cnt] 0000000000000022 - C_GetAttributeValue
[pid] 230885
[ppd] 230878
[tid] 230885
[tic] 2023-06-28 16:32:50.903702
[in ] hSession = 0x8cb
[in ] hObject = 0x470
[in ] pTemplate[29]: 
      CKA_TOKEN             0000000000000000 / 0
      CKA_PRIVATE           0000000000000000 / 0
      CKA_MODIFIABLE        0000000000000000 / 0
      CKA_LABEL             0000000000000000 / 0
      CKA_KEY_TYPE          0000000000000000 / 0
      CKA_ID                0000000000000000 / 0
      CKA_START_DATE        0000000000000000 / 0
      CKA_END_DATE          0000000000000000 / 0
      CKA_DERIVE            0000000000000000 / 0
      CKA_DERIVE_TEMPLATE   0000000000000000 / 0
      CKA_LOCAL             0000000000000000 / 0
      CKA_KEY_GEN_MECHANISM 0000000000000000 / 0
      CKA_ALLOWED_MECHANISMS  0000000000000000 / 0
      CKA_ENCRYPT           0000000000000000 / 0
      CKA_DECRYPT           0000000000000000 / 0
      CKA_SIGN              0000000000000000 / 0
      CKA_VERIFY            0000000000000000 / 0
      CKA_WRAP              0000000000000000 / 0
      CKA_WRAP_TEMPLATE     0000000000000000 / 0
      CKA_UNWRAP            0000000000000000 / 0
      CKA_UNWRAP_TEMPLATE   0000000000000000 / 0
      CKA_SENSITIVE         0000000000000000 / 0
      CKA_ALWAYS_SENSITIVE  0000000000000000 / 0
      CKA_EXTRACTABLE       0000000000000000 / 0
      CKA_NEVER_EXTRACTABLE 0000000000000000 / 0
      CKA_CHECK_VALUE       0000000000000000 / 0
      CKA_TRUSTED           0000000000000000 / 0
      CKA_WRAP_WITH_TRUSTED  0000000000000000 / 0
      CKA_VALUE_LEN         0000000000000000 / 0
[out] pTemplate[29]: 
      CKA_TOKEN             0000000000000000 / 1
      CKA_PRIVATE           0000000000000000 / 1
      CKA_MODIFIABLE        0000000000000000 / 1
      CKA_LABEL             0000000000000000 / 25
      CKA_KEY_TYPE          0000000000000000 / 8
      CKA_ID                0000000000000000 / 15
      CKA_START_DATE        0000000000000000 / 8
      CKA_END_DATE          0000000000000000 / 8
      CKA_DERIVE            0000000000000000 / 1
      CKA_DERIVE_TEMPLATE   0000000000000000 / -1 (CK_UNAVALABLE_INFORMATION)
      CKA_LOCAL             0000000000000000 / 1
      CKA_KEY_GEN_MECHANISM 0000000000000000 / 8
      CKA_ALLOWED_MECHANISMS  0000000000000000 / 0
      CKA_ENCRYPT           0000000000000000 / 1
      CKA_DECRYPT           0000000000000000 / 1
      CKA_SIGN              0000000000000000 / 1
      CKA_VERIFY            0000000000000000 / 1
      CKA_WRAP              0000000000000000 / 1
      CKA_WRAP_TEMPLATE     0000000000000000 / 96
      CKA_UNWRAP            0000000000000000 / 1
      CKA_UNWRAP_TEMPLATE   0000000000000000 / 144
      CKA_SENSITIVE         0000000000000000 / 1
      CKA_ALWAYS_SENSITIVE  0000000000000000 / 1
      CKA_EXTRACTABLE       0000000000000000 / 1
      CKA_NEVER_EXTRACTABLE 0000000000000000 / 1
      CKA_CHECK_VALUE       0000000000000000 / -1 (CK_UNAVALABLE_INFORMATION)
      CKA_TRUSTED           0000000000000000 / 1
      CKA_WRAP_WITH_TRUSTED  0000000000000000 / 1
      CKA_VALUE_LEN         0000000000000000 / 8
[toc] 2023-06-28 16:32:50.903757
[lap] 0.000055
[ret] 0 CKR_OK
```

The following sample contains even more information, as the template is returned populated by the PKCS\#11 library:

```
[cnt] 0000000000000023 - C_GetAttributeValue
[pid] 230885
[ppd] 230878
[tid] 230885
[tic] 2023-06-28 16:32:50.903759
[in ] hSession = 0x8cb
[in ] hObject = 0x470
[in ] pTemplate[29]: 
      CKA_TOKEN             00000000018b7150 / 1
      CKA_PRIVATE           00000000018b6630 / 1
      CKA_MODIFIABLE        00000000018a82a0 / 1
      CKA_LABEL             00000000018b9150 / 25
      CKA_KEY_TYPE          00000000018a8260 / 8
      CKA_ID                00000000018a8280 / 15
      CKA_START_DATE        00000000018a81c0 / 8
      CKA_END_DATE          00000000018a8120 / 8
      CKA_DERIVE            00000000018adf30 / 1
      CKA_DERIVE_TEMPLATE   0000000000000000 / 0
      CKA_LOCAL             00000000018ade90 / 1
      CKA_KEY_GEN_MECHANISM 00000000018addb0 / 8
      CKA_ALLOWED_MECHANISMS  00000000018add10 / 0
      CKA_ENCRYPT           00000000018adc30 / 1
      CKA_DECRYPT           00000000018a8fa0 / 1
      CKA_SIGN              00000000018a31b0 / 1
      CKA_VERIFY            00000000018a3110 / 1
      CKA_WRAP              00000000018a3030 / 1
      CKA_WRAP_TEMPLATE     00000000018b89b0 / 96
      CKA_UNWRAP            00000000018a2f90 / 1
      CKA_UNWRAP_TEMPLATE   00000000018a3900 / 144
      CKA_SENSITIVE         00000000018a8f80 / 1
      CKA_ALWAYS_SENSITIVE  00000000018a8ee0 / 1
      CKA_EXTRACTABLE       00000000018a8e00 / 1
      CKA_NEVER_EXTRACTABLE 00000000018a8de0 / 1
      CKA_CHECK_VALUE       0000000000000000 / 0
      CKA_TRUSTED           00000000018a8d40 / 1
      CKA_WRAP_WITH_TRUSTED  00000000018a8d20 / 1
      CKA_VALUE_LEN         00000000018b9050 / 8
[out] pTemplate[29]: 
      CKA_TOKEN             True
      CKA_PRIVATE           True
      CKA_MODIFIABLE        True
      CKA_LABEL             00000000018b9150 / 25
      74657374 2D32322D 6175672D 30335F61 65735772 61704B65 79
       t e s t  - 2 2 -  a u g -  0 3 _ a  e s W r  a p K e  y
      CKA_KEY_TYPE          CKK_AES            
      CKA_ID                00000000018a8280 / 15
      00000000  61 65 73 32 35 36 2D 31 36 36 30 32 36 37 38     aes256-16602678 
      CKA_START_DATE        00000000018a81c0 / 8
      00000000  30 30 30 30 30 30 30 30                          00000000        
      CKA_END_DATE          00000000018a8120 / 8
      00000000  30 30 30 30 30 30 30 30                          00000000        
      CKA_DERIVE            False
      CKA_DERIVE_TEMPLATE   0000000000000000 / -1 (CK_UNAVALABLE_INFORMATION)
      CKA_LOCAL             True
      CKA_KEY_GEN_MECHANISM True
      CKA_ALLOWED_MECHANISMS  00000000018add10 / 0
      CKA_ENCRYPT           False
      CKA_DECRYPT           False
      CKA_SIGN              False
      CKA_VERIFY            False
      CKA_WRAP              True
      CKA_WRAP_TEMPLATE     00000000018b89b0 / 96
      00000000  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
      00000010  01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00  ................
      00000020  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00  ................
      00000030  07 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
      00000040  01 00 00 00 00 00 00 00 05 01 00 00 00 00 00 00  ................
      00000050  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00  ................
      CKA_UNWRAP            True
      CKA_UNWRAP_TEMPLATE   00000000018a3900 / 144
      00000000  03 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
      00000010  01 00 00 00 00 00 00 00 62 01 00 00 00 00 00 00  ........b.......
      00000020  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00  ................
      00000030  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
      00000040  01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00  ................
      00000050  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00  ................
      00000060  07 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
      00000070  01 00 00 00 00 00 00 00 05 01 00 00 00 00 00 00  ................
      00000080  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00  ................
      CKA_SENSITIVE         True
      CKA_ALWAYS_SENSITIVE  True
      CKA_EXTRACTABLE       False
      CKA_NEVER_EXTRACTABLE True
      CKA_CHECK_VALUE       0000000000000000 / -1 (CK_UNAVALABLE_INFORMATION)
      CKA_TRUSTED           False                                     .               
      CKA_WRAP_WITH_TRUSTED False                                       .               
      CKA_VALUE_LEN         00000000018b9050 / 8
      00000000  20 00 00 00 00 00 00 00                           .......        
[toc] 2023-06-28 16:32:50.903833
[lap] 0.000074
[ret] 0 CKR_OK
```

## Authors
Eric Devolder
`libpkcs11shim` is forked from `pkcs11-spy` of the [OpenSC project](https://github.com/OpenSC/OpenSC); original authors referred in this project and in relevant source files.

## Licensing and warranty
Licensed under [LGPL 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html); please refer to the license terms for details about licensing and warranty.


