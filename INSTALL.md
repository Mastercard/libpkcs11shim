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

## Windows 64-bit (cross-compiling with Podman)

The recommended way to build the Windows 64-bit DLL is using the provided Dockerfile with Podman:

### Build

```bash
podman build -f buildx/Dockerfile.mingw64 -t libpkcs11shim-win64 .
```

### Extract

```bash
podman create --name win64-extract --entrypoint /bin/true localhost/libpkcs11shim-win64
mkdir -p output-win64
podman cp win64-extract:/libpkcs11shim-0.dll ./output-win64/
podman cp win64-extract:/libgcc_s_seh-1.dll ./output-win64/
podman cp win64-extract:/libwinpthread-1.dll ./output-win64/
podman rm win64-extract
```

The `output-win64/` directory will contain:
- `libpkcs11shim-0.dll` — the PKCS#11 shim library
- `libwinpthread-1.dll` — pthreads runtime
- `libgcc_s_seh-1.dll` — GCC runtime

Copy the entire contents to your Windows machine to use.
