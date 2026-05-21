# Build notes for g++ on Ubuntu and MinGW on Windows

This project can be built without Visual Studio. The board side uses `g++` on Ubuntu, and the PC-side TA can be built with MinGW on Windows 11.

## 1. Ubuntu / RK3566 development board

Install dependencies:

```bash
sudo apt update
sudo apt install -y g++ make libsodium-dev pkg-config
```

Build with the direct g++ Makefile:

```bash
make -f Makefile.gcc
```

The executables will be generated under `build_gcc/`:

```text
build_gcc/provision_tool
build_gcc/ta_server
build_gcc/device_client
```

On the board, usually only `device_client` is needed:

```bash
./build_gcc/device_client --show-hwid
./build_gcc/device_client --server <TA-PC-IP> --port 9000 --store device_store.conf
```

## 2. Windows 11 + MinGW, recommended MSYS2 method

Open the **MSYS2 MinGW64** shell, not the plain MSYS shell. Install dependencies:

```bash
pacman -Syu
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-libsodium mingw-w64-x86_64-pkgconf make
```

Build:

```bash
make -f Makefile.gcc
```

The executables will be generated under `build_gcc/`:

```text
build_gcc/provision_tool.exe
build_gcc/ta_server.exe
build_gcc/device_client.exe
```

On the PC, usually only these two are needed:

```bash
./build_gcc/provision_tool.exe --hwid <device-hwid> --token <token>
./build_gcc/ta_server.exe --db ta_db.conf --key ta_key.conf --port 9000
```

Windows Firewall must allow inbound TCP for the selected port, for example `9000`.

## 3. Standalone MinGW + prebuilt libsodium

If you are not using MSYS2 packages, download the MinGW build of libsodium and extract it, for example to:

```text
C:/libsodium-win64
```

The directory should contain:

```text
C:/libsodium-win64/include/sodium.h
C:/libsodium-win64/lib/libsodium.a or libsodium.dll.a
```

Then build:

```bash
make -f Makefile.gcc SODIUM_PREFIX=C:/libsodium-win64
```

If `make` runs under `cmd.exe` and does not understand `mkdir -p`, use the MSYS2 MinGW64 shell instead, or compile manually:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -Iinclude -IC:/libsodium-win64/include \
  src/common.cpp src/mincosig.cpp src/net.cpp src/protocol.cpp src/provision_tool.cpp \
  -LC:/libsodium-win64/lib -lsodium -lws2_32 -o provision_tool.exe

g++ -std=c++17 -O2 -Wall -Wextra -Iinclude -IC:/libsodium-win64/include \
  src/common.cpp src/mincosig.cpp src/net.cpp src/protocol.cpp src/ta_server.cpp \
  -LC:/libsodium-win64/lib -lsodium -lws2_32 -o ta_server.exe
```

If using the shared library, put `libsodium-*.dll` in the same directory as the `.exe`, or add its `bin` directory to `PATH`.

## 4. Optional CMake + MinGW

CMake also works with MinGW:

```bash
cmake -G "MinGW Makefiles" -S . -B build_mingw
cmake --build build_mingw -j
```

If CMake cannot find libsodium, pass the paths explicitly:

```bash
cmake -G "MinGW Makefiles" -S . -B build_mingw \
  -DSODIUM_INCLUDE_DIR=C:/libsodium-win64/include \
  -DSODIUM_LIBRARY=C:/libsodium-win64/lib/libsodium.a
cmake --build build_mingw -j
```

## 5. Timing measurement commands

TA side:

```bash
./build_gcc/ta_server.exe --db ta_db.conf --key ta_key.conf --port 9000 --perf-csv server_perf.csv
```

Device side:

```bash
./build_gcc/device_client --server <TA-PC-IP> --port 9000 --store device_store.conf \
  --token <token> --pwd <pwd> --perf-csv device_perf.csv
```

The terminal output and CSV files report message-level local processing time. The device reports `M1/M2/M3/M4` device-side time; the TA reports `M1/M2/M3/M4` server-side time. Network waiting time is excluded.
