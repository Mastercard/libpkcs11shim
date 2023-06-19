# libpkcs11shim : a shim library for PKCS#11

## Introduction
`libpkcs11shim` is a shim library that can insert itself between an application and a target PKCS#11 library. The project is actually a fork on a small part of [OpenSC project on GitHub](https://github.com/OpenSC/OpenSC), called [`pkcs11-spy`](src/pkcs11/pkcs11-spy.c). In addition to `pkcs11-spy`, `libpkcs11shim` adds some capabilities:
 - cleaner log output
 - ability to capture logs in a multithreaded environment
 - ability to carry on capture upon fork of the calling process
 - provides a deferred logging capability, reducing significantly the impact on performance on a library being logged (at the cost of extra memory allocation)
 - microsecond resolution for API call, allowing to identify library performance problems
 - hides passphrase information by default (that can be overriden by an environment variable, see options below)

## Building libpkcs11shim

To build the library:
 1. clone the repo from GitHub
 2. From the repo directory, execute `./bootstrap.sh`
 3. execute `./configure`. As usual, configure script contains several options that can be useful to better match your environment.
 4. execute `make`
 5. optionally, `make install`. The library is named `libpkcs11shim.so` and is deployed by default to `/usr/local/lib`.

## Usage

to use this library:
- define `PKCS11SHIM` environment variable to point to the original PKCS#11 library
- specify the `libpkcs11shim.so` library as the PKCS#11 library to use
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


## Authors
Eric Devolder. 
`libpkcs11shim` is forked from `pkcs11-spy` of the [OpenSC project](https://github.com/OpenSC/OpenSC); original authors referred in this project and in relevant source files.

## Licensing and warranty
Licensed under [LGPL 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html); please refer to the license terms for details about licensing and warranty.

