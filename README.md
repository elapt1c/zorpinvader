# ZorpInvader

**Internet-scale API key scanner** — finds exposed secrets across the entire IPv4 space in under 6 minutes.

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
| `--shard n/m` | Distributed scanning | `1/1` |
| `--seed <n>` | Random seed | random |
| `--selftest` | Run regression tests | — |

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
├── main.rs              # Entry point, transmit/receive threads
├── lib.rs               # Library root
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
