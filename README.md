# libpkcs11shim : a shim library for PKCS#11

## Usage

to use this library:
- define `PKCS11SHIM` environment variable to point to the original PKCS#11 library
- specify the `libpkcs11shim.so` library as the application library
- run your program as usual.

### options
The following environment variables can be defined, to adjust the logging behaviour:

- `PKCS11SHIM_OUTPUT`, when present, specifies a filename where the log entries should be written. Fi the file already exists, logs will be appended to it. If the filename contains `%p`, it will be replaced with the pid of the running process. When `PKCS11SHIM_OUTPUT` is not specified, output goes to `/dev/stderr`.
- `PKCS11SHIM_CONSISTENCY`; when present, allows to adjust how consistent are logs, in a multithreaded environment:

 * `0` (basic)
   Logs are directly written, from the same thread, to the output file. Logs are therefore synchronous with the thread execution. If several threads are running concurrently, log entries may overlap. The basic mode is adequate for single-threaded executions.
 * `1` (consistent callblocks)
   Logs are still written from the same thread as the caller, but there is a mutex preventing log entries to overlap, within one calling block. As a consequence, log entries will never overlap for multithreaded executions. However, it has a significant impact on performance. Use this mode for logging on multithreaded executions, where impact on performance is acceptable, or if you absolutely need to print log entries synchronously with other output.
 * `2` (deferred)
   Log entries are pushed to a queue. There is a queue worker that takes care of emptying the queue, in a separate thread. This mode provides good performance, and guarantees that no overlap may occur accross threads. However it is memory-hungry, and log output is deferred, which means you can't rely on the log entry to be printed in sync with other output. Use this mode for logging on multithreaded execution, where impact on performance must be minimized, at the expense of memory consumption and loss of synchronicity between logs and other output. Beware: this mode may overflow memory, if writing to the output can't keep up with the rate of incoming messages. You have been warned.


