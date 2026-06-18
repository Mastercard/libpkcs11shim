# Installation

## Using pre-built binaries
Pre-built binaries are available for download from the release page. This is the simplest option, but you may be lacking the latest features.

## Using Docker on Linux
Provided that Docker is deployed on your system, you can build the library using the `buildx.sh` script, which is located in the root directory of the project. This script automates the process of building the library for various distributions and architectures. For each target platform, both a tarball and a distribution-specific package (`.deb`, `.rpm`, `.apk`) are built.

To build the library using Docker for your architecture, you can use the following command (in this example, we are building for Ubuntu 24.04):
```bash
$ ./buildx.sh ubuntu2404
```

You can specify more than one target distribution at once, for example:
```bash
$ ./buildx.sh ol9 ubuntu2404 deb12
```

Provided that your environment supports multiple architectures (using `qemu`), you can cross-compile the library. For each target platform, you can specify the architecture. Note that `all` means to build for all available architectures, i.e. `x86_64` and `aarch64` in this occurence. For example:
```bash
$ ./buildx.sh ol9/amd64 ubuntu2404/arm64 deb12/all
```

`buildx.sh` supports parallel building, and comes with a number of options to specify the target distribution, the target architecture, the repository URL, the commit/tag/branch to build, and so on. You can see the help message by running:
```bash
$ ./buildx.sh --help
```

By default `buildx.sh` clones the repository from the remote URL. To build directly from your local checkout (including any committed local changes) without going through the network, use `--local-source`:
```bash
$ ./buildx.sh --local-source ubuntu2404
```
This works for any target, including `mingw64`.

### Supported distributions
The following distributions are supported by the `buildx.sh` script:

| Distribution | Distribution short name (to use with `buildx.sh`) |
|--------------|---------------------------------------------------|
| Oracle Linux 9 | `ol9` |
| Oracle Linux 8 | `ol8` |
| Oracle Linux 7 | `ol7` |
| Debian 12 (Bookworm) | `deb12` |
| Ubuntu 24.04 (Noble Numbat) | `ubuntu2404` |
| Ubuntu 22.04 (Jammy Jellyfish) | `ubuntu2204` |
| Alpine Linux 3.21 | `alpine321` |
| Amazon Linux 2023 | `amzn2023` |
| Windows 64-bit (MinGW-w64 cross-compile) | `mingw64` |

## Building from source (Linux)

### Prerequisites

Install the required build tools:

**RHEL/Oracle Linux/Fedora:**
```bash
dnf install -y gcc make automake autoconf autoconf-archive libtool git
```

**Debian/Ubuntu:**
```bash
apt-get install -y gcc make automake autoconf autoconf-archive libtool git
```

### Build

```bash
./bootstrap.sh
./configure
make -j$(nproc)
```

### Install

```bash
sudo make install
```

### Clean and rebuild

```bash
make distclean
./bootstrap.sh
./configure
make -j$(nproc)
```

## Windows 64-bit (cross-compiling with Docker)
Windows 64-bit binaries are produced via MinGW-w64 cross-compilation, using the same `buildx.sh` workflow as the other supported distros. This requires Docker (Podman with a `docker` alias works as well):

```bash
$ ./buildx.sh mingw64
```

The build produces two archives in the current directory:
- `libpkcs11shim-mingw64-x86_64-<version>.zip` (Windows-friendly format)
- `libpkcs11shim-mingw64-x86_64-<version>.tar.gz`

Each archive contains the PKCS#11 shim DLL and its required runtime DLLs, along with the documentation:
- `libpkcs11shim-0.dll` — the PKCS#11 shim library
- `libwinpthread-1.dll` — pthreads runtime
- `libgcc_s_seh-1.dll` — GCC runtime

Extract the archive on your Windows machine to use the library.

Notes:
- Unlike the other distros, the `mingw64` target always produces Windows `x86_64` binaries regardless of the host architecture (it uses the MinGW-w64 cross-compiler inside a Fedora container).
- All standard `buildx.sh` options (`--repo`, `--commit`, `--skip-git-sslverify`, etc.) apply.
