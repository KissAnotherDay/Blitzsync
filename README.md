# BlitzSync

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)](#building-from-source)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)

**BlitzSync** is a high-speed, multi-threaded, cross-platform file synchronization and transfer tool engineered as a native alternative to `rsync` for **Windows ↔ Linux** workflows—with **zero WSL, Cygwin, or persistent server daemons required**.

Written in Go, BlitzSync compiles into a single self-contained native executable for Windows (`blitzsync.exe`) and Linux (`blitzsync`). It features a built-in native Go SSH/TCP transport stack, block-level delta synchronization, parallel disk I/O, real-time throughput telemetry, and end-to-end SHA-256 integrity verification.

---

## Table of Contents

- [Why BlitzSync?](#why-blitzsync)
- [Architecture](#architecture)
- [Installation](#installation)
  - [Option 1: Download Pre-Built Binaries](#option-1-download-pre-built-binaries)
  - [Option 2: Build from Source](#option-2-build-from-source)
  - [Deploy the Worker Binary on Linux](#deploy-the-worker-binary-on-linux)
- [Quick Start & Examples](#quick-start--examples)
- [CLI Options](#cli-options)
- [SSH Configuration (`~/.ssh/config`)](#ssh-configuration-sshconfig)
- [Performance Tuning](#performance-tuning)
- [Data Integrity & Security](#data-integrity--security)
- [License](#license)

---

## Why BlitzSync?

- **True Native Windows & Linux Binaries:** Eliminates Cygwin DLLs, `/cygdrive/` path translation issues, and WSL virtualization overhead.
- **Built-In High-Speed Go SSH Engine:** Connects directly over a tuned TCP socket (`TCP_NODELAY`, 4 MB socket buffers, hardware-accelerated `aes128-gcm@openssh.com`), bypassing the Windows OpenSSH `stdin` pipe bottleneck.
- **Zero Server Daemon (`rsync`-style):** No background service or extra open firewall ports needed. BlitzSync invokes its remote worker automatically over SSH (`blitzsync --server`) and communicates via a custom framed binary protocol (`BZSC`).
- **Multi-Threaded I/O & Hashing Pipeline:** Concurrent worker pools handle directory scanning, block SHA-256 hashing, parallel `ReadAt` disk reads, and parallel `WriteAt` disk writes.
- **Block-Level Delta Transfer:** Large files (4K videos, VM disk images, archives) are split into configurable blocks (default `1 MB`, recommended `8 MB` for media). Only modified blocks travel over the network; unchanged blocks are copied locally at the destination.
- **Real-Time Progress & Network Speed:** Displays a live progress bar updated every 150 ms with transfer percentage, transferred/total bytes, sliding-window connection speed (`MB/s`), ETA, and bytes saved via delta sync.
- **Guaranteed Bit-for-Bit Integrity:**
  - Every transmitted block is validated via **SHA-256** before being written to disk.
  - Files are staged into isolated `.blitzsync.tmp` files, flushed with `fsync`, verified with a **full-file SHA-256 digest read back from disk**, and atomically renamed—preventing corrupted or truncated video and binary files.

---

## Architecture

```text
+-----------------------------------+                           +-----------------------------------+
|         Windows Client            |    Native Go TCP / SSH    |            Linux Host             |
|         (blitzsync.exe)           |   (AES-128-GCM, 4MB buf)  |       (blitzsync --server)        |
+-----------------------------------+                           +-----------------------------------+
| 1. Walk source directory tree     | --- MsgManifest --------> | 2. Compare size/mtime metadata    |
|                                   | <--- MsgSyncPlan -------- |    & parallel hash delta blocks   |
| 3. Parallel Worker Pool (-t N):   |                           | 4. Parallel Worker Pool (-t N):   |
|    - Concurrent ReadAt() blocks   | === MsgBlockData =======> |    - Verify per-block SHA-256     |
|    - Compute block SHA-256        | --- MsgBlockCopy -------> |    - Concurrent WriteAt() to .tmp |
|    - Stream full-file SHA-256     | --- MsgFileCommit ------> |    - fsync() & full-file SHA-256  |
|    - Live MB/s & ETA telemetry    | <--- MsgFileAck --------- |    - Atomic rename to final path  |
+-----------------------------------+                           +-----------------------------------+
```

---

## Installation

### Option 1: Download Pre-Built Binaries

Download the latest executables from the **[Releases](../../releases)** page:
- **Windows (64-bit):** `blitzsync-windows-amd64.exe` (rename to `blitzsync.exe` and place in a folder included in your `PATH`)
- **Linux (64-bit x86):** `blitzsync-linux-amd64`
- **Linux (ARM64 / Raspberry Pi):** `blitzsync-linux-arm64`

### Option 2: Build from Source

Requires **Go 1.22+**.

#### On Windows (PowerShell)
```powershell
# Download dependencies
go mod tidy

# Build Windows executable
go build -ldflags="-s -w" -o blitzsync.exe .

# Cross-compile Linux (x86_64) binary
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags="-s -w" -o blitzsync .
```

#### On Linux / macOS (Bash)
```bash
# Download dependencies
go mod tidy

# Build Linux binary
go build -ldflags="-s -w" -o blitzsync .

# Cross-compile Windows executable
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o blitzsync.exe .
```

### Deploy the Worker Binary on Linux

Copy the Linux `blitzsync` binary to your remote Linux machine into a directory listed in `$PATH` (so non-interactive SSH sessions can execute it):

```bash
# System-wide installation (requires sudo)
sudo install -m 0755 blitzsync /usr/local/bin/blitzsync

# Or user-only installation (no sudo required)
mkdir -p ~/.local/bin
install -m 0755 blitzsync ~/.local/bin/blitzsync
```

> **Note:** If you install in `~/.local/bin/blitzsync` and it is not in your non-interactive SSH `$PATH`, pass `--remote-bin ~/.local/bin/blitzsync` when running BlitzSync.

---

## Quick Start & Examples

```text
blitzsync [options] <source> <destination>
```

### 1. Push Large Video Files from Windows to Linux
Use 8 MB blocks (`-b 8192`) and 8 parallel threads (`-t 8`) for maximum throughput on large media files:
```powershell
blitzsync.exe -b 8192 -t 8 "C:\Media\Videos" user@192.168.1.50:/mnt/storage/videos
```

### 2. Pull Backups from Linux to Windows
```powershell
blitzsync.exe -t 8 user@192.168.1.50:/var/backups/projects "D:\Backups\projects"
```

### 3. Specify a Custom SSH Private Key and Port
```powershell
blitzsync.exe -i "C:\Users\alice\.ssh\id_ed25519" -p 2222 "C:\Data" alice@example.com:/srv/data
```

### 4. Mirror a Directory (Preview First with `--dry-run`)
```powershell
# Preview changes without modifying any files
blitzsync.exe --delete --dry-run "C:\Photos" user@192.168.1.50:/mnt/nas/photos

# Apply mirror sync (deletes extraneous files at destination)
blitzsync.exe --delete "C:\Photos" user@192.168.1.50:/mnt/nas/photos
```

### 5. Force Full Block-by-Block SHA-256 Verification
Ignore quick `size + mtime` checks and verify every block of every file against the destination:
```powershell
blitzsync.exe --verify -t 12 "C:\Archives" user@192.168.1.50:/mnt/archives
```

---

## CLI Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-t`, `--threads <int>` | CPU core count | Number of parallel workers for block hashing, disk reads, and disk writes. |
| `-b`, `--block-size <int>` | `1024` | Block size in KB used for delta comparison and chunked transfers. |
| `-i`, `--identity <string>` | Auto-detected | Path to SSH private key file (also reads `~/.ssh/config` and SSH Agent). |
| `-p`, `--port <int>` | `22` | Remote SSH port (overrides `~/.ssh/config`). |
| `-e`, `--ssh <string>` | Built-in Go SSH | Optional external SSH binary command (e.g. `"ssh -p 2222"`). Uses native Go SSH when omitted. |
| `--remote-bin <string>` | `"blitzsync"` | Path to the `blitzsync` binary on the remote host if not in `$PATH`. |
| `--verify` | `false` | Force full block-by-block SHA-256 verification even when file size and mtime match. |
| `--delete` | `false` | Delete files and empty directories on the destination that do not exist in the source. |
| `--dry-run` | `false` | Display the sync plan (`[FULL]` / `[DELTA]`) without transferring or deleting data. |
| `-v`, `--version` | — | Print version, OS, and CPU architecture and exit. |
| `-h`, `--help` | — | Show CLI help message. |

---

## SSH Configuration (`~/.ssh/config`)

BlitzSync automatically parses `C:\Users\<YourUser>\.ssh\config` (Windows) and `~/.ssh/config` (Linux/macOS), including `Host`, `HostName`, `User`, `Port`, and `IdentityFile`, as well as active SSH agents (`openssh-ssh-agent` on Windows, `SSH_AUTH_SOCK` on Linux).

### Pro Tip: Separate LAN and WAN Host Aliases
If your server is on your local network, routing via a public domain may trigger **NAT Loopback (hairpinning)** on your router and cap speeds to your router's CPU or ISP link. Define two aliases in `~/.ssh/config`:

```text
# Direct LAN connection (full 1 Gbps / 2.5 Gbps / 10 Gbps switch speed)
Host server-lan
    HostName 192.168.1.50
    User marco
    Port 22
    IdentityFile "C:\Users\aless\.ssh\id_ed25519"

# External WAN connection (when away from home)
Host server-wan
    HostName example.com
    User marco
    Port 2929
    IdentityFile "C:\Users\aless\.ssh\id_ed25519"
```

Then simply run:
```powershell
blitzsync.exe -b 8192 -t 8 "C:\Media\Videos" server-lan:/home/marco/videos
```

---

## Performance Tuning

- **Large Video / ISO / Archive Files:** Use `-b 8192` (8 MB blocks) and `-t 8` to minimize protocol framing overhead while saturating NVMe drives and multi-gigabit links.
- **Thousands of Small Files:** Keep the default `-b 1024` and set `-t` to match your physical CPU cores (`-t 8` or `-t 16`).
- **Mechanical Hard Drives (HDD):** Lower concurrency to `-t 2` or `-t 4` to avoid excessive disk head seeking on spinning drives.

---

## Data Integrity & Security

- **End-to-End Cryptographic Verification:** Every block frame carries its own `SHA-256` digest verified before writing; upon completion, the receiver reads back the staged `.blitzsync.tmp` file from disk, computes a full-file `SHA-256`, and compares it against the sender's stream hash before performing an atomic rename.
- **Directory Traversal Protection:** All relative paths are normalized and validated (`SafeJoin`) on the receiver to prevent path traversal outside the target root directory.
- **Strict Host Key Checking:** Validates server fingerprints against `~/.ssh/known_hosts` with interactive confirmation on first connection.

---

## License

MIT License — free to use, modify, and distribute.