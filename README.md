# ZorpInvader

**Internet-scale API key scanner** — finds exposed secrets across the entire IPv4 space

ZorpInvader performs asynchronous SYN stealth scanning using raw sockets, discovers open HTTP ports, fetches web pages and JavaScript bundles, then detects leaked API keys using Aho-Corasick multi-pattern matching against **54 known provider prefixes**. Discovered keys are verified live against **47 provider APIs** and written to CSV.

## How It Works

```
SYN probe → SYN-ACK → open port detected
  → HTTP GET http://ip:port/
  → parse HTML + extract <script src="…">
  → fetch non-CDN JavaScript files
  → Aho-Corasick scan for API key prefixes
  → heuristic false-positive filtering
  → deduplication cache (16K entries)
  → live provider API verification
  → confirmed keys → found_keys.csv
```

### Pipeline Components

| Component | Description |
|-----------|-------------|
| **Transmit thread** | BlackRock-shuffled SYN probes via `AF_PACKET` raw sockets |
| **Receive thread** | Stateless SYN-ACK parsing with SipHash-2-4 cookie verification |
| **HTTP Fetcher** | Multi-threaded `curl`-based page/JS fetcher with CDN filtering |
| **Key Scanner** | Aho-Corasick engine matching 54 API key prefixes |
| **Verifier** | 47 provider-specific live verification functions |

## Supported Providers

AWS, Google, GitHub, Stripe, OpenAI, Slack, Anthropic, Groq, DeepSeek, Mistral, Nvidia, Cohere, Fireworks, Together, HuggingFace, DigitalOcean, GitLab, CircleCI, SendGrid, Fastly, Cloudflare, Heroku, Azure, Alibaba/DashScope, Twitter/X, Discord, PayPal, Meta/Facebook, Twilio, PyPI, Mailgun, Square, Linear, Sentry, NPM, RubyGems, Vercel, OpenRouter, Voyage, ElevenLabs, Replicate, AssemblyAI, Flutterwave, and more.

## Install (prebuilt)

Release binaries are statically linked against musl and built for baseline CPU
features (no `-C target-cpu=native`), so they run on any Linux — x86-64 or
aarch64, glibc or musl, container or bare metal — with no toolchain, no
libpcap and no glibc version pinning:

```bash
# x86-64
curl -fsSL -o zorpinvader \
  https://github.com/elapt1c/zorpinvader/releases/latest/download/zorpinvader-x86_64-linux-musl

# aarch64 (Raspberry Pi, ARM VPS, Apple-silicon VM)
curl -fsSL -o zorpinvader \
  https://github.com/elapt1c/zorpinvader/releases/latest/download/zorpinvader-aarch64-linux-musl

chmod +x zorpinvader && sudo mv zorpinvader /usr/local/bin/
sudo zorpinvader --version
```

```text
ZorpInvader version 1.4.0 (https://github.com/elapt1c/zorpinvader)
OS: linux  Architecture: x86_64
Libc: musl (static)
```

Each asset ships with a `.sha256` file; check it with `sha256sum -c`. Tarballs
are provided too, for hosts that would rather unpack than download a raw binary.

The full runtime dependency list is:

| Need | Why |
|------|-----|
| root, or `CAP_NET_RAW`+`CAP_NET_ADMIN` | raw `AF_PACKET` sockets for the SYN probes |
| `curl` | page/JS fetching and the client's control channel |
| `tor` (optional) | only for `--tor` / `.onion`; one is supervised automatically, or an existing one on 9050 is reused |

Kernel 3.17 or newer for `AF_PACKET` and `SO_RCVTIMEO` semantics as used here.
Nothing else is required on the target machine.

## Build

```bash
# Debug build
cargo build

# Optimized release build (recommended for scanning)
./build.sh
```

The release profile uses `opt-level=3`, fat LTO, single codegen unit, and native CPU tuning for maximum packet processing throughput.

## Usage

```bash
# Scan common HTTP ports across the internet at 10k pps
sudo ./bin/zorpinvader --rate 10000 -p 80,8080,8443,8000,3000,5000,8888

# Target a specific range
sudo ./bin/zorpinvader --rate 5000 --range 10.0.0.0/8 -p 80,443

# Use the watchdog for long-running scans (auto-restarts every 30 min)
sudo ./run.sh 10000 16 "80,8080,8443,8000,3000,5000,8888"

# Resume where the last run stopped (coverage, not a byte offset)
sudo ./bin/zorpinvader --resume --rate 10000 -p 80,443
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--rate <n>` | Packets per second | `100` |
| `-p <ports>` | Target ports | `80,8080,8443,8000,3000,5000,8888` |
| `--range <cidr>` | Target IP range | `0.0.0.0/0` |
| `--exclude <cidr>` | Exclude IP range | RFC1918 + reserved |
| `--tpc <n>` | Fetcher threads per core | `16` |
| `--adapter <name>` | Network interface | auto-detect |
| `--adapter-ip <ip>` | Source IP | auto-detect |
| `--retries <n>` | Number of retransmits | `0` |
| `--shard n/m` | Static sharding of the block set | `1/1` |
| `--seed <n>` | Random seed (block order, probe shuffle) | random |
| `--resume` | Accepted for compatibility; an existing progress file resumes | always |
| `--reset` | Start over, ignoring an existing progress file | off |
| `--state <file>` | Progress file (coverage, leases, onion, token) | `zorpinvader.progress` |
| `--results-dir <dir>` | Where results are written | `.` |
| `--job-size <addrs>` | Addresses per job block | auto |
| `--server [port]` | Run a controller (port optional with `--tor`) | auto |
| `--server-bind <ip>` | Controller listen address | `0.0.0.0` |
| `--client <url>` | Join a controller and scan its blocks | — |
| `--client-name <name>` | Client name in the controller status | hostname |
| `--token <secret>` | Optional shared secret; without it the controller is open | — |
| `--lease <seconds>` | Lease on an unresponsive client's block | `180` |
| `--tor` | Publish the controller on an onion service / force a client through tor | off |
| `--tor-socks <h:p>` | Use an existing tor SOCKS proxy instead of starting one | auto (9050/9150) |
| `--tor-binary <path>` | Explicit `tor` binary | from PATH |
| `--tor-dir <dir>` | tor DataDirectory | next to the progress file |
| `--tor-timeout <s>` | Bootstrap timeout | `180` |
| `--selftest` | Run regression tests | — |

## Distributed scanning

There are three ways to run, all on the same engine:

| Mode | Command | What it does |
|------|---------|--------------|
| Standalone | `zorpinvader --rate 10000 -p 80,443` | Schedules and scans in one process |
| Controller | `zorpinvader --server 8000 -p 80,443 --rate 40000` | Plans blocks, allocates them, aggregates results. Never transmits. |
| Client | `zorpinvader --client https://zi.example.dev --token …` | Claims a block, scans it, reports hits and keys |

```bash
# Controller on a small VM, published through a Cloudflare tunnel
zorpinvader --server 8000 -p 80,443 --rate 40000 --token "$TOKEN"
cloudflared tunnel --url http://localhost:8000     # gives https://…trycloudflare.com

# Any number of scanners, each on a host with the network path
sudo zorpinvader --client https://zi.example.dev --token "$TOKEN"
sudo zorpinvader --client http://ctrl.internal:8000 --token "$TOKEN"
```

The controller speaks plain HTTP/1.1 and clients use `curl`, so TLS is whatever
terminates the public endpoint (`cloudflared`, Caddy, nginx) and the client trusts
the system CA store. Nothing TLS-specific lives in this binary.

### How work is allocated

It is a pull queue of leased CIDR blocks, one block per worker at a time:

```
worker                                    controller
  │  POST /api/v1/claim  ───────────────▶  pick the next block, lease it
  │  ◀───────────────  10.9.0.4/30, ports, rate share, resume offset
  │  scan the block (shuffled order inside it)
  │  POST /api/v1/progress (every 5s)  ─▶  renew lease, update dashboard
  │  POST /api/v1/results               ▶  hits + keys, de-duplicated
  │  POST /api/v1/complete              ▶  mark covered, free the lease
  │  POST /api/v1/claim  ───────────────▶  next block …
  │  ◀───────────────  {"done": true}      exit
```

No worker holds more than one block, nothing is assigned up front, and the
controller never transmits. A worker that dies mid-block has its lease expire;
the block is handed to the next worker that asks, resuming at the probe offset
the dead worker last reported.

* The target set is divided into **CIDR-aligned blocks** (`--job-size`, or
  automatically so a plan stays under 65,536 blocks).
* The controller hands blocks out in a **seeded shuffled order**, so a partial
  scan is spread across the address space instead of walking it front to back.
  Within a block, probes go through a BlackRock permutation, so the wire order is
  random too.
* Every block is **leased**, not assigned (`--lease`, default 180 s). A client that
  stops reporting loses its block, which goes back to the pool and resumes at the
  last reported position. A dead machine costs at most one lease interval of
  duplicated work.
* `--rate` on the controller is an **aggregate**: it is divided between connected
  clients and rebalanced as they come and go. A client's own `--rate` is a
  ceiling, so `min(share, ceiling)` applies.

The controller never scans, so it needs no raw sockets; the clients need the same
privileges a standalone scan does.

### Resume is coverage, not a cursor

A scan's progress is a **set of addresses**, not an index into a shuffled space:

* A completed block adds its interval to the covered set.
* Resuming means `targets - covered`, which is exact and independent of how many
  clients ran, or which machine did what.
* The state file stores that set as a **minimal CIDR decomposition**, so it grows
  with the number of *gaps* in coverage, not with the number of addresses. A
  thousand contiguous `/24`s cost one interval, not 256,000 entries.

Merging is done on intervals, which is exact, and each merged interval is then
decomposed into the fewest CIDRs that cover it. Two adjacent `/24`s at
`1.2.3.0/24` and `1.2.4.0/24` merge into one interval — but no single CIDR covers
exactly that interval (a `/23` has to start on an even `/23` boundary), so it
serialises back as the same two CIDRs. Adjacent runs that *are* aligned do
collapse: `1.2.2.0/24` + `1.2.3.0/24` becomes `1.2.2.0/23`.

```bash
zorpinvader --resume --rate 10000 -p 80,443      # continue
zorpinvader --reset  --rate 10000 -p 80,443      # start over
```

The progress file is `zorpinvader.progress`. A state file without `--resume` is
an error rather than something silently overwritten. Changing `--job-size` between runs keeps every completed address
(coverage is per address); only in-block resume offsets are dropped.

### Results

The controller owns the authoritative copy:

* `open_ports.csv` — `ip,port,client,job,timestamp`, one row per newly seen port.
* `found_keys.csv` — confirmed keys, identical schema to the standalone output.

Both are de-duplicated against what is already on disk, so a client re-delivering
after a retry cannot inflate them. Clients keep their own `found_keys.csv` for
local inspection and spool anything the controller could not accept to
`zorp-spool-<client>.jsonl`, retrying on the next block and at startup — results
are delivered independently of scheduling, so a late delivery is still accepted
after a lease expires.

### Control API

All endpoints are JSON over HTTP, authenticated with `Authorization: Bearer <token>`
(except `/healthz`). `--server` prints the token if none is supplied.

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/join` | Register, receive ports/blocks/lease settings |
| `POST /api/v1/claim` | Lease the next block (or `done`) |
| `POST /api/v1/progress` | Renew the lease, report position and counters |
| `POST /api/v1/results` | Deliver hits and keys (independent of the lease) |
| `POST /api/v1/complete` | Mark a block covered |
| `POST /api/v1/release` | Give a block back unfinished |
| `GET /api/v1/status` | Blocks, coverage, rate, ETA, clients |
| `GET /api/v1/coverage` | Covered and remaining CIDRs |

```bash
curl -H "Authorization: Bearer $TOKEN" https://zi.example.dev/api/v1/status | jq
```

Static sharding (`--shard n/m`) still works for sharded runs: each shard keeps
every `m`-th block, so several machines with the same plan do not overlap.

## TUI

ZorpInvader features a real-time terminal UI during scans:

```
 ZorpInvader │ Status: Scanning │ Keys: 12/847/29103
 Rate: 62.81 kpps │ Progress: 14.2% │ ETA: 02:14:33 │ Found: 51703
──────────────────────────────────────────────────────────────────────────────
[  KEY SCAN LOG  ]
[CONFIRMED] sk-ws-H.RPDPIHE.Gkdo...PqR  │ dashscope
[REJECTED]  ghp_abcdefghijk...xyz12     │ GitHub Personal Access Token
[DETECTED]  AIzaSyBxxxxxxxxxxxxxxx       │ Google API Key
[CONFIRMED] ghp_R8k2mNxPq...vW4z │ GitHub Personal Access Token
...
──────────────────────────────────────────────────────────────────────────────
Fetcher: pages=29103 scripts=847 │ gzip=12 html=28991 <script>=4102 │ queue=312
Valid: 12 │ Invalid: 835 │ Pending: 4
```

## Over Tor

A controller can publish itself as an onion service, and a client can reach it
with nothing but the address — no port to open, no tunnel, no certificates.
`--tor` implies controller mode, so there is no port to choose and no listener to
expose: the local HTTP port is picked automatically and bound to `127.0.0.1`,
which is all tor needs.

```bash
# --tor is a controller on its own: it picks a local port on loopback,
# publishes <56 chars>.onion and writes it to the progress file
zorpinvader --tor -p 80,443 --rate 40000

# any worker, from anywhere — the address is the only argument needed
zorpinvader --client q3uod25xuv32meewcju6awkxszr2pobzqum34itj27sz34lmxnwe7bad.onion
```

The controller is **open by default**: whoever has the address can join, like a
room code. If you want it private, start it with `--token SECRET` and pass the
same `--token` to workers — an unauthenticated worker is then rejected with
`401 this controller requires a token`.

Everything a worker needs is in the progress file, so the controller can be
started on one machine and a worker on another by copying one line:

```bash
$ cat zorpinvader.progress | jq -r .connect
zorpinvader --client q3uod….onion
```

The file also carries `onion`, `url`, `listen` and `token`, and is written `0600`
because of the token.

```
{
  "onion": "q3uod25xuv32meewcju6awkxszr2pobzqum34itj27sz34lmxnwe7bad.onion",
  "url": "http://q3uod….onion",
  "listen": "0.0.0.0:8000",
  "token": "",
  "connect": "zorpinvader --client q3uod….onion",
  "done": ["10.9.0.0/28"], "partial": [], "next_ptr": 4, "syns": 16
}
```

A `.onion` target makes the client use tor automatically; `--tor` forces it for
a non-onion address. The client finds tor in this order:

1. `--tor-socks host:port` if given (validated with a real SOCKS5 handshake);
2. a tor already listening on `127.0.0.1:9050` or `9150`, reused as-is;
3. a private instance it starts itself on an ephemeral SOCKS port.

The controller always starts its own instance, because publishing a hidden
service needs a `HiddenServiceDir`. Both roles wait for `Bootstrapped 100%` and
report progress while they do.

### Why tor is a supervised process, not a library

Speaking the Tor protocol in-process would be the wrong engineering trade here.
Arti, the Rust implementation, still marks onion-service *hosting* experimental
and ships it behind `__is_experimental` APIs (arti 2.7 / `tor-hsservice` 0.47), and
the C tor is the only implementation with a track record of publishing services.
So ZorpInvader supervises a real `tor`:

* it never downloads a binary — a missing `tor` is an error naming the install
  command for your platform;
* each instance gets its own DataDirectory, SOCKS port and hidden-service keys,
  so it cannot collide with a tor you already run;
* a pidfile is used to reap a tor that outlived a crashed run, and it is only
  signalled after checking that its command line names the same DataDirectory;
* on a clean shutdown (including SIGTERM) the supervised instance is stopped.

If you would rather manage Tor yourself, `--tor-socks 127.0.0.1:9050` with a
system tor works for clients, and the controller can sit behind any tunnel.

## Controller dashboard

With a terminal attached, the controller draws a live view: aggregate progress,
one row per node sorted by throughput, and the same scrolling key log the
standalone scan shows, tagged with the node that found each key.

```
 ZorpInvader controller │ q3uod25x….onion │ 12m34s
 Coverage:  50.00%  Blocks: 2/4  Addresses: 512/1024  Rate: 61.2k/s  ETA: 39s
 Clients: 4  Inflight: 4  Partial: 0  Hits: 1  Keys: 2
──────────────────────────────────────────────────────────────────────────────
 NODE             BLOCK                  PROG   BAR               PPS   HITS  KEYS IDLE
 node-alpha       10.9.1.0/24             28.1% [███·······]     14.1k      0     0   3s
 node-beta        10.9.3.0/24             28.1% [███·······]     13.9k      0     0   3s
──────────────────────────────────────────────────────────────────────────────
[  KEY LOG  ]
  00:49:27  EXAMPLEKEY_a…2345             stripe       node-alpha       10.9.0.7
  00:49:27  EXAMPLEKEY_b…6789             github       node-beta        10.9.1.42
──────────────────────────────────────────────────────────────────────────────
 JOIN  25vw2s4mrt5yb6rgyb5mr3kraxdyrocfuvmznf2dgaf6776akqrneqyd.onion
 copy: zorpinvader --client 25vw2s4mrt5yb6rgyb5mr3kraxdyrocfuvmznf2dgaf6776akqrneqyd.onion
```

When a token is configured it appears next to the address (`│ token …`) and in
the copy line.

The `JOIN` panel is pinned to the bottom for the whole run, like a room code:
the address stays on screen and selectable, so a new node can be added at any
point by copying that line. It shows the onion address when `--tor` is on, and
the dialable `http://` URL otherwise.

Clients report telemetry every 5 seconds (block, position, rate, hits, keys);
the controller redraws every second. Without a terminal — systemd, a log file —
the same information is printed as periodic plain lines instead.

## Output

Confirmed keys are written to `found_keys.csv`:

```csv
confirmed,ip_address,api_key,provider,category,timestamp
1,203.0.113.42,AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_M3namBGewQe,Google API Key,google,2026-08-21T14:30:00Z
```

Status codes: `1` = confirmed, `2` = detected (unverified), `3` = exhausted.

## Requirements

- **Linux** with `AF_PACKET` support (raw sockets)
- **Root** privileges
- **curl** (`/usr/bin/curl`) for HTTP fetching and API verification
- **Rust** toolchain for building

## Architecture

```
src/
├── main.rs              # Entry point and mode dispatch
├── lib.rs               # Library root
├── coord/               # Distributed scanning
│   ├── set4.rs          # IPv4 set algebra, minimal CIDR decomposition
│   ├── plan.rs          # targets → aligned blocks, block ordering
│   ├── scheduler.rs     # leases, coverage, state file, results de-dup
│   ├── protocol.rs      # JSON wire format
│   ├── http.rs          # minimal HTTP/1.1 server
│   ├── server.rs        # controller: handlers around the scheduler
│   ├── client.rs        # client loop (curl transport, SOCKS5 for .onion)
│   ├── tor.rs           # supervised tor: onion service + SOCKS5
│   ├── dashboard.rs     # multi-node live view + shared key log
│   └── local.rs         # standalone mode, same scheduler in-process
├── engine/              # Scan unit
│   ├── scan_unit.rs     # ScanEngine: adapter + pipeline, one block at a time
│   ├── hits.rs          # per-block open-port collection
│   └── keys.rs          # tails found_keys.csv for confirmed keys
├── greyhat/
│   ├── greyhat.rs       # Aho-Corasick key scanner (54 patterns)
│   ├── fetcher.rs       # Multi-threaded HTTP fetcher
│   └── verifier.rs      # Provider API verification (47 providers)
├── crypto/              # BlackRock cipher, SipHash, LCG
├── massip/              # IP/port range management
├── rawsock/             # AF_PACKET raw sockets, adapter detection
├── templ/               # Packet templates (TCP SYN, UDP, ICMP)
├── stack/               # ARP, NDP, TCP state machine
├── proto/               # Protocol parsers (HTTP, SSL, SSH, etc.)
├── output/              # Output formats (JSON, XML, text, etc.)
├── main_mod/            # Config, status TUI, throttle, dedup
├── data/                # Smack (Aho-Corasick), ring buffers
├── pixie/               # Portable timers, threads
├── misc/                # SYN cookies, RST filter
└── util/                # Checksums, error handling
```

## License

[AGPL-3.0](LICENSE)

## Disclaimer

This tool is intended for **authorized security research and responsible disclosure** only. Scanning networks you do not own or have explicit permission to test may violate laws in your jurisdiction. Always obtain proper authorization before scanning. Use responsibly.
