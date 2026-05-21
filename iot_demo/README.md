# IoT Collaborative Ownership Binding Demo

This is a C++17 + libsodium prototype for the collaborative EdDSA-based IoT onboarding protocol described in the paper draft.

It contains three executables:

- `provision_tool`: simulates manufacturing/provisioning and generates the preloaded device store and TA database.
- `ta_server`: runs on the PC-side TA, tested target environment: Windows 11.
- `device_client`: runs on the IoT development board, tested target environment: Ubuntu.

The implementation uses:

- Ed25519 low-level group operations from libsodium for Min-CoSig-style collaborative EdDSA.
- X25519 for ephemeral session key agreement in the online protocol.
- Ed25519 standard signatures for TA authentication (`alpha`) and default-device authorization proof (`beta`).
- XChaCha20-Poly1305 as the AEAD instance of `Enc_k` / `Dec_k`.
- HKDF-SHA256 implemented with libsodium HMAC-SHA256.
- Argon2id via `crypto_pwhash()` for `PBKDF(PWD, HWID)`.


## Build with g++ / MinGW directly

A direct `g++` Makefile is also provided for the target setup where the board uses Ubuntu `g++` and the PC uses MinGW. See `README_BUILD_GCC_MINGW.md`.

Quick commands:

```bash
# Ubuntu / RK3566
sudo apt install -y g++ make libsodium-dev pkg-config
make -f Makefile.gcc

# Windows 11 / MSYS2 MinGW64
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-libsodium mingw-w64-x86_64-pkgconf make
make -f Makefile.gcc
```

## Build on Ubuntu / RK3566 board

```bash
sudo apt update
sudo apt install -y build-essential cmake libsodium-dev

cmake -S . -B build
cmake --build build -j
```

## Build on Windows 11 with vcpkg

Install libsodium:

```powershell
vcpkg install libsodium:x64-windows
```

Then build:

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

The executables will be under `build/Release/` with Visual Studio generators, or directly under `build/` with single-config generators.

## Step 1: read the device HWID on Ubuntu

On the development board:

```bash
./build/device_client --show-hwid
```

This reads `/proc/cpuinfo` and extracts the CPU `Serial` field. If your board does not expose `Serial`, pass `--hwid <value>` manually to the client and provisioner.

## Step 2: provisioning

Run this on the PC or any machine with libsodium. Replace the HWID and Token with your values.

```bash
./build/provision_tool --hwid 00000000abcdef12 --token 12345678
```

It generates:

- `device_store.conf`: copy this file to the board.
- `ta_db.conf`: keep this on the TA PC.
- `ta_key.conf`: keep this on the TA PC; `ta_pub` is also embedded into `device_store.conf`.

The provisioning tool computes the preloaded information corresponding to the paper:

- `salt_d`, `salt_s`, `salt = salt_d xor salt_s`
- `K = HKDF(Token, salt, HWID)`
- `ciphertext_def = Enc_K(Pri_def)`
- server-side collaborative share `sk2`, nonce seed `v2`, and `pk2 = sk2 * G`
- device-side preload tuple: `<HWID, ciphertext_def, salt_d, pk2, Pub_TA>`
- TA-side tuple: `<HWID, Token, Pub_def, salt_s, H(salt_d), sk2, v2, pk2>`

## Step 3: start TA server on Windows 11

```powershell
.\build\Release\ta_server.exe --db ta_db.conf --key ta_key.conf --port 9000
```

Make sure Windows Firewall allows inbound TCP on this port.

## Step 4: run device onboarding on Ubuntu board

Copy `device_store.conf` to the board and run:

```bash
./build/device_client --server <TA-PC-IP> --port 9000 --store device_store.conf
```

The client will ask for `Token` and `PWD`. You can also pass them non-interactively:

```bash
./build/device_client --server <TA-PC-IP> --port 9000 --store device_store.conf --token 12345678 --pwd mypassword
```

On success, the device writes:

- `device_user_secret.conf`, containing `C_usr = Enc_{PBKDF(PWD,HWID)}(sk1 || v1)` and `Pub_usr`.

The TA database is updated with:

- `consumed=1`
- `pub_usr=<hex>`


## Timing measurement

Both `device_client` and `ta_server` now print local processing time for the four protocol messages. Network waiting time for `send()` / `recv()` is excluded, so the numbers mainly reflect local cryptographic and protocol processing.

Run the TA with optional CSV output:

```bash
./build_gcc/ta_server.exe --db ta_db.conf --key ta_key.conf --port 9000 --perf-csv server_perf.csv
```

Run the device with optional CSV output:

```bash
./build_gcc/device_client --server <TA-PC-IP> --port 9000 --store device_store.conf \
  --token 12345678 --pwd mypassword --perf-csv device_perf.csv
```

The four message-level timing items are:

| Message | Device-side timing | Server-side timing |
|---|---|---|
| M1 | generate request: key share, `Q_d`, `N_d`, `xid`, `R1`, and message assembly | process request: parse, validate Token/`H(salt_d)`, validate `pk1/R1`, compute `xid`, `Pub_usr`, and `m_co` |
| M2 | process response: derive `sk`, decrypt `C_salt`, verify `alpha`, recover `Pri_def` | generate response: generate `Q_s/N_s`, derive `sk`, sign `alpha`, compute `R/S2`, encrypt `C_salt` |
| M3 | generate ownership message: finish collaborative signature, generate `beta`, encrypt M3 | process ownership message: decrypt M3, verify `beta`, verify collaborative signature, update TA database |
| M4 | process ACK: decrypt and verify ACK | generate ACK: encrypt ACK and assemble M4 |

`device_client` also prints an `Extra` item for protecting and storing `sk1||v1` with `PBKDF(PWD,HWID)`. This item is intentionally not included in the four message timings because password-based local storage can dominate the measurement and is not part of the online message-processing cost.

## Message mapping

Online message fields:

- `M1 = <Token, Q_d, N_d, H(salt_d), T1, pk1, R1>`
- `M2 = <Q_s, N_s, T2, alpha, C_salt, R, S2>`
- `M3 = <xid, Enc_sk(beta || sigma_usr || T3)>`
- `M4 = Enc_sk(Ack || T4)`

The collaborative signature is computed as:

```text
Pub_usr = sk1 * pk2 = sk1 * sk2 * G
m_co    = H(HWID || Pub_usr || pk1 || xid)
r1      = H(v1 || m_co)
R1      = r1 * G
r2      = H(v2 || m_co || R1)
R       = R1 + r2 * pk1
S2      = r2 + H(R || Pub_usr || m_co) * sk2 mod n
S       = r1 + sk1 * S2 mod n
sigma   = R || S
```

The final `sigma` is verified with libsodium's standard Ed25519 verification API under `Pub_usr`.

## Important limitations

This is a research prototype, not production firmware:

- The demo stores secrets in simple key-value files.
- The server handles one onboarding session at a time in a simple loop.
- Token is transmitted in `M1` exactly as in the current paper model.
- The demo does not implement persistent anti-rollback protection for `C_usr` or `PWD` retry limits.
- Real products should protect local files, counters, device state, and password-derived secrets using platform-specific mechanisms.
