<div align="center">

```

██████╗               ███████╗███████╗ █████╗      █████╗ ██████╗ ██╗    ██╗ █████╗ ██╗  ██╗
██╔══██╗              ██╔════╝╚════██║██╔══██╗    ██╔══██╗██╔══██╗██║    ██║██╔══██╗██║  ██║
██████╔╝   ██████╔    ███████╗   ██╔╝ ╚██████║    ███████║██████╔╝██║ █╗ ██║███████║███████║
██╔══██╗              ╚════██║  ██╔╝   ╚═══██║    ██╔══██║██╔══██╗██║███╗██║██╔══██║██╔══██║
██████╔╝              ███████║  ██║    █████╔╝    ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║
╚═════╝               ╚══════╝  ╚═╝    ╚════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝
  
       
                                                                                                 
 A R W A H  ·  B - 5 7 9
```

**Network Scanner — Rust Workspace + C Core**

[![CI](https://github.com/you/b579-arwah/actions/workflows/ci.yml/badge.svg)](https://github.com/you/b579-arwah/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Rust: nightly](https://img.shields.io/badge/rust-nightly-orange)](https://www.rust-lang.org/)
[![Platform: Linux · macOS · Windows](https://img.shields.io/badge/platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-lightgrey)](#)

</div>

---

## What is B-579 Arwah?

**B-579 Arwah** a high-performance, modular network scanner built as a Rust workspace with a custom C core.

It is not a script wrapper. It is not a GUI around someone else's engine. Every packet that leaves your NIC was crafted by Arwah from scratch — raw bytes, raw sockets, zero external scanning logic.

The architecture is built around one idea: **each concern lives in exactly one place**. The C layer handles what C does best — raw memory, platform-specific syscalls, SIMD checksums. The Rust layer handles everything else — async orchestration, type safety, plugin loading, structured output.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    b579-arwah-cli                        │  ← you talk here
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                      b579-arwah                          │  ← public facade
└──┬──────────┬────────┬────────┬──────────┬──────────────┘
   │          │        │        │          │
   ▼          ▼        ▼        ▼          ▼
engine     output   plugin   crypto      range
   │
   ├── scan ──── probe ──── net ──── utils
   │                          │
   │                 ┌────────▼────────┐
   │                 │   C / FFI layer │
   │                 ├─────────────────┤
   │                 │  librawsock     │  raw sockets (POSIX / Winsock2)
   │                 │  libpacket      │  Ethernet/IP/TCP/UDP/ICMP craft
   │                 │  libcrypto      │  checksums, PRNG, nonce
   │                 │  libplatform    │  OS detection, endianness
   │                 └────────┬────────┘
   │                          │
   │                 ┌────────▼────────┐
   └──────────────── │ system libpcap  │  packet capture
                     │ / npcap (Win)   │
                     └─────────────────┘
```

### Crates

| Crate | Type | Role |
|---|---|---|
| `b579-arwah` | lib | Public facade — `pub use` everything |
| `b579-arwah-proto` | lib | Core types, traits, contracts — no logic |
| `b579-arwah-engine` | lib | Orchestrator — runs scan, probe, throttle |
| `b579-arwah-scan` | lib | Scan strategies — SYN, connect, UDP, ICMP |
| `b579-arwah-probe` | lib | Packet send/receive — banners, fingerprints |
| `b579-arwah-net` | lib | Raw socket abstraction, FFI bridge to C |
| `b579-arwah-range` | lib | IP range parsing — CIDR, wildcards, lists |
| `b579-arwah-crypto` | lib | Nonce generation, hashing, source port rand |
| `b579-arwah-output` | lib | JSON, CSV, table, custom format rendering |
| `b579-arwah-plugin` | lib | Plugin trait + dynamic loader |
| `b579-arwah-utils` | lib | Logging, helpers, shared utilities |
| `b579-arwah-cli` | **bin** | The only binary |

### C Libraries (in `libs/`)

| Library | What it does |
|---|---|
| `libplatform` | OS/arch detection, endianness — everything depends on this |
| `librawsock` | Raw socket open/send/recv — POSIX on Unix, Winsock2 on Windows |
| `libpacket` | Zero-copy packet construction and parsing (Eth/IP/TCP/UDP/ICMP) |
| `libcrypto` | IP/TCP/UDP checksums (SIMD-optimized), nonce generation |

---

## Features

- **Raw packet crafting** — every byte is yours, no kernel TCP stack involved in SYN scan
- **Async engine** — Tokio-based, thousands of concurrent probes without thread-per-connection overhead
- **Rate limiting** — token bucket throttle, configurable packets/sec so you don't nuke your own network
- **Service fingerprinting** — banner grabbing, protocol detection via the plugin system
- **Plugin architecture** — write your own probe logic, load it at runtime
- **Cross-platform** — Linux, macOS, Windows (Npcap)
- **Structured output** — JSON, CSV, or formatted table, pipe-friendly
- **Zero external scanner logic** — the engine is ours, not a wrapper

---

## Performance

Full IPv4 space is ~4.3 billion addresses.

| Hardware | Expected throughput | Full internet (SYN scan) |
|---|---|---|
| 1 Gbps NIC, modern CPU | ~1M pkt/s | ~70 min |
| 10 Gbps NIC + ring buffer | ~10M pkt/s | ~7 min |
| 10 Gbps + DPDK / AF_XDP | ~25M pkt/s | ~3 min |

> Arwah targets the 10M pkt/s range via `PACKET_MMAP` ring buffer on Linux and async batch sending on all platforms.
> Actual speed depends on your NIC, kernel settings, and network upstream rate limit.

Saturating a 10G NIC requires:
- `librawsock` sending via `PACKET_MMAP` (Linux) or `AF_PACKET`
- Receive side running in a separate async task
- `arwah-engine` throttle backed off only when the send ring is full

This is the roadmap, not the first release. But the architecture is built for it from day one.

---

## Platform Support

| OS | Capture | Raw Send | Status |
|---|---|---|---|
| Linux (x86_64, ARM64) | libpcap | `AF_PACKET` + `PACKET_MMAP` | ✅ Primary |
| macOS (x86_64, ARM64) | libpcap | BPF | ✅ Supported |
| Windows (x86_64) | Npcap | Winsock2 raw | ✅ Supported |
| FreeBSD / OpenBSD | libpcap | BPF | 🔜 Planned |

---

## Requirements

### Linux / macOS
```bash
# Linux
sudo apt install libpcap-dev

# macOS
brew install libpcap
```
Root or `CAP_NET_RAW` capability required for raw sockets.

### Windows
Install [Npcap](https://npcap.com/) with WinPcap compatibility mode.
Run as Administrator.

---

## Build

```bash
git clone https://github.com/you/b579-arwah
cd b579-arwah

# Build everything
cargo build --workspace --release

# Run
./target/release/arwah --help
```

---

## Usage

```bash
# SYN scan a single host, common ports
arwah scan 192.168.1.1

# CIDR range, specific ports, JSON output
arwah scan 10.0.0.0/8 --ports 22,80,443,8080 --output json

# Full TCP connect scan with banner grabbing
arwah scan 192.168.0.0/24 --mode connect --probe banner

# Rate-limited scan (1000 pkt/s)
arwah scan 172.16.0.0/12 --rate 1000

# Load a custom plugin
arwah scan 10.0.0.1 --plugin ./my_probe.so
```

---

## Project Layout

```
b579-arwah/
├── crates/                  # Rust workspace members
│   ├── b579-arwah/          # facade
│   ├── b579-arwah-engine/
│   ├── b579-arwah-net/
│   ├── b579-arwah-scan/
│   ├── b579-arwah-proto/
│   ├── b579-arwah-probe/
│   ├── b579-arwah-crypto/
│   ├── b579-arwah-range/
│   ├── b579-arwah-output/
│   ├── b579-arwah-plugin/
│   └── b579-arwah-utils/
├── b579-arwah-cli/          # binary
├── libs/                    # C core (libplatform, librawsock, libpacket, libcrypto)
├── tests/                   # integration tests
├── scripts/                 # dev tooling
├── data/                    # fingerprint databases, port lists
├── .github/workflows/       # CI + Release
├── Dockerfile
├── docker-compose.yml
├── Cargo.toml               # workspace root
├── rustfmt.toml
├── rust-toolchain.toml
├── clippy.toml
└── b579.sh / b579.bat       # platform bootstrap scripts
```

---

## Docker

```bash
# Build image
docker build -t b579-arwah .

# Run scan (NET_RAW required for raw sockets)
docker run --rm --cap-add NET_RAW --network host b579-arwah scan 192.168.1.0/24
```

---

## Contributing

Open an issue before a PR. Describe what you're changing and why.

Code style is enforced by `rustfmt` (nightly, see `rustfmt.toml`) and `clippy` (see `clippy.toml`).

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
```

---

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

---

<div align="center">

*Built from raw bytes up.*

</div>
