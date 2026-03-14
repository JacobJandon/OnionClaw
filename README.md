# OnionClaw 🧅

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/JacobJandon/OnionClaw/blob/main/LICENSE)
[![OpenClaw Skill](https://img.shields.io/badge/OpenClaw-skill-blueviolet)](https://github.com/JacobJandon/OnionClaw)

**by JacobJandon**

<p align="center">
  <img src="OnionClawTransparent.png" alt="OnionClaw logo" width="200"/>
</p>

> **OpenClaw skill + standalone tool** — full Tor / dark web access for AI agents

OnionClaw gives AI agents full access to the Tor network and .onion hidden services. It runs as an [OpenClaw](https://github.com/openclaw/openclaw) skill (drop-in, zero config beyond a `.env` file) and also works standalone from any terminal.

Based on the [SICRY](https://github.com/JacobJandon/Sicry) engine — 18 dark web search engines, Robin OSINT pipeline, four LLM analysis modes.

```bash
# As an OpenClaw skill:
cp -r OnionClaw ~/.openclaw/skills/onionclaw
# → agent now has 7 dark web commands available in every session

# Standalone:
python3 scripts/check_tor.py        # verify Tor
python3 scripts/search.py --query "ransomware healthcare"
python3 scripts/pipeline.py --query "acme.com data leak" --mode corporate
```

---

## Contents

1. [What OnionClaw does](#what-onionclaw-does)
2. [Requirements](#requirements)
3. [Install as OpenClaw skill](#install-as-openclaw-skill)
4. [Standalone install](#standalone-install)
5. [Configuration](#configuration)
6. [All seven commands](#all-seven-commands)
7. [Investigation flows](#investigation-flows)
8. [Analysis modes](#analysis-modes)
9. [Troubleshooting](#troubleshooting)
10. [Credits](#credits)

---

## What OnionClaw does

Seven commands expose the complete Tor OSINT toolkit:

| Command | What it does |
|---|---|
| `check_tor.py` | Verify Tor is active, show current exit IP |
| `renew.py` | Rotate Tor circuit — new exit node, new identity |
| `check_engines.py` | Ping all 18 dark web search engines, show latency |
| `search.py` | Search up to 18 engines simultaneously, deduplicated results |
| `fetch.py` | Fetch any `.onion` or clearnet URL through Tor |
| `ask.py` | LLM OSINT analysis of scraped content (4 modes) |
| `pipeline.py` | Full Robin pipeline: refine → search → filter → scrape → analyse |

---

## Requirements

- **Python 3.10+**
- **Tor** running locally (SOCKS proxy on `127.0.0.1:9050`)
- **pip packages**: `requests[socks] beautifulsoup4 python-dotenv stem`
- **LLM key** (optional — only needed for `ask.py` and `pipeline.py` analysis step)

### Install Tor

**Linux (Debian/Ubuntu):**
```bash
apt install tor && tor &
```

**macOS:**
```bash
brew install tor && tor &
```

**With control port (needed for `renew.py`):**
```bash
cat > /tmp/onionclaw_tor.conf << 'EOF'
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /tmp/tor_data
EOF
tor -f /tmp/onionclaw_tor.conf &
```
Then set `TOR_DATA_DIR=/tmp/tor_data` in `.env`.

### Install Python packages

```bash
pip install requests[socks] beautifulsoup4 python-dotenv stem
```

---

## Install as OpenClaw skill

1. **Clone or copy** this repo into your OpenClaw skills directory:

```bash
# Option A — clone directly
git clone https://github.com/Ps3wb4n/OnionClaw ~/.openclaw/skills/onionclaw

# Option B — copy local folder
cp -r OnionClaw ~/.openclaw/skills/onionclaw
```

2. **Configure** `.env` in the skill folder:

```bash
cp ~/.openclaw/skills/onionclaw/.env.example ~/.openclaw/skills/onionclaw/.env
nano ~/.openclaw/skills/onionclaw/.env   # add LLM key if desired
```

3. **Start a new OpenClaw session** — the skill loads automatically on startup. OpenClaw includes `onionclaw` in the agent context whenever the user asks about dark web topics.

**Verify OpenClaw can see the skill:**
```bash
openclaw skills list
# → onionclaw  🧅  Search the Tor dark web...
```

**OpenClaw trigger phrases:**
- "search the dark web for …"
- "investigate this .onion site …"
- "check if my data appeared on the dark web"
- "find ransomware leaks related to …"
- "fetch this .onion URL …"
- "run a Tor OSINT investigation on …"

> After install, start a **new session** — existing sessions will not pick up the new skill.

---

## Standalone install

No OpenClaw required. Every script runs directly from a terminal:

```bash
git clone https://github.com/JacobJandon/OnionClaw
cd OnionClaw
pip install requests[socks] beautifulsoup4 python-dotenv stem
cp .env.example .env
# Edit .env — add LLM key if desired (optional for most commands)
```

---

## Configuration

Copy `.env.example` to `.env` and fill in what you need:

```dotenv
# ── Tor ────────────────────────────────────────────────────────────────
TOR_SOCKS_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_HOST=127.0.0.1
TOR_CONTROL_PORT=9051
# TOR_CONTROL_PASSWORD=your_password   # only if HashedControlPassword in torrc
# TOR_DATA_DIR=/tmp/tor_data           # DataDirectory path for cookie auth

# ── LLM (needed only for ask.py and pipeline.py analysis step) ──────────
LLM_PROVIDER=openai          # openai | anthropic | gemini | ollama | llamacpp
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GEMINI_API_KEY=AIza...
# OLLAMA_MODEL=llama3.2       # local model — no API key needed
```

> **No LLM key?** Set `LLM_PROVIDER=ollama` with a running Ollama instance for fully local inference. `search.py`, `fetch.py`, `check_tor.py`, `renew.py`, and `check_engines.py` work with no LLM key at all.

---

## All seven commands

### `check_tor.py` — verify Tor

```bash
python3 scripts/check_tor.py
```

```
✓ Tor active
  Exit IP  : 185.220.101.20
  Error    : None
{"tor_active": true, "exit_ip": "185.220.101.20", "error": null}
```

Run this before anything else. Exits with code 1 if Tor is not running or not accessible on port 9050.

---

### `renew.py` — rotate identity

```bash
python3 scripts/renew.py
```

```
Rotating Tor circuit...
✓ Identity renewed — new Tor circuit established
{"success": true, "error": null}
```

Auth order: password env var → cookie from `TOR_DATA_DIR` → common system paths → null auth. Works out of the box with the recommended torrc above or with a standard system Tor install.

---

### `check_engines.py` — engine health check

```bash
python3 scripts/check_engines.py
```

```
ALIVE  13/18
──────────────────────────────────────────
  ✓  Ahmia-clearnet       670ms  ███
  ✓  Tor66                749ms  ███
  ✓  Ahmia               1139ms  █████
  ✓  OSS                 1203ms  ██████
  ...
DOWN   5/18
  ✗  Kaizer     timeout
  ✗  Anima      timeout
  ✗  FindTor    timeout
```

Run before a large search session. Use the alive engine names as arguments to `--engines` in `search.py`.

---

### `search.py` — search dark web

```bash
# All 18 engines (default)
python3 scripts/search.py --query "ransomware healthcare leak"

# Specific engines (faster — use alive engines from check_engines output)
python3 scripts/search.py \
  --query "credential dump" \
  --engines Ahmia Tor66 Ahmia-clearnet OSS

# Limit result count
python3 scripts/search.py --query "bitcoin mixer" --max 30
```

Returns a deduplicated `{title, url, engine}` list across all engines.

**Tip:** Use short keyword queries (3–5 words). Dark web search indexes respond much better to keywords than natural-language sentences.

---

### `fetch.py` — fetch any .onion page

```bash
# Hidden service
python3 scripts/fetch.py \
  --url "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"

# With links extracted
python3 scripts/fetch.py --url "http://example.onion/page" --links

# JSON output only
python3 scripts/fetch.py --url "http://example.onion" --json
```

Returns: title, text content (up to 8000 chars), extracted links, HTTP status code. A status of `0` means the hidden service is unreachable or offline.

---

### `ask.py` — LLM OSINT analysis

```bash
# Inline content
python3 scripts/ask.py \
  --query "LockBit ransomware" \
  --mode ransomware \
  --content "page text from scraped pages"

# From file
python3 scripts/ask.py \
  --query "acme.com" \
  --mode corporate \
  --file /tmp/scraped_pages.txt

# Pipe from fetch.py
python3 scripts/fetch.py --url "http://some.onion" --json | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['text'])" | \
  python3 scripts/ask.py --query "investigate" --mode threat_intel

# Custom analysis focus
python3 scripts/ask.py \
  --query "mixer services" \
  --mode threat_intel \
  --content "..." \
  --custom "Focus on cryptocurrency wallet addresses only"
```

**Modes:** `threat_intel` · `ransomware` · `personal_identity` · `corporate` — see [Analysis modes](#analysis-modes).

---

### `pipeline.py` — full investigation (one command)

Runs the complete Robin OSINT pipeline automatically:

| Step | What happens |
|---|---|
| 1 | Verify Tor is active |
| 2 | Check which engines are alive |
| 3 | Refine query to ≤5 keywords (LLM) |
| 4 | Search all alive engines |
| 5 | Filter top 20 most relevant results (LLM) |
| 6 | Batch-scrape pages concurrently |
| 7 | OSINT analysis and report (LLM) |

```bash
# Basic
python3 scripts/pipeline.py --query "hospital ransomware 2026"

# With analysis mode and output file
python3 scripts/pipeline.py \
  --query "acme.com credentials leak" \
  --mode corporate \
  --out report.md

# Full options
python3 scripts/pipeline.py \
  --query "QUERY" \
  --mode ransomware \
  --max 50 \
  --scrape 12 \
  --custom "Focus on ransom amounts and victim industries" \
  --out report.md
```

**Steps 1–6 work fully without an LLM key.** Only steps 3, 5, and 7 use the LLM — they fall back gracefully when no key is set, printing what was collected so far.

---

## Investigation flows

### Scenario 1: Check for leaked credentials

```bash
python3 scripts/check_tor.py
python3 scripts/pipeline.py \
  --query "acme.com email passwords" \
  --mode corporate \
  --scrape 10 \
  --out acme_leak_report.md
```

### Scenario 2: Ransomware intelligence

```bash
python3 scripts/check_tor.py
python3 scripts/search.py \
  --query "LockBit healthcare 2026" \
  --engines Ahmia Tor66 Ahmia-clearnet \
  --max 40

# Fetch the most relevant URL
python3 scripts/fetch.py --url "http://..." > /tmp/page.json

# Analyse
python3 scripts/ask.py \
  --query "LockBit healthcare 2026" \
  --mode ransomware \
  --file /tmp/page.json
```

### Scenario 3: Personal data exposure check

```bash
python3 scripts/pipeline.py \
  --query "john.smith@email.com personal data" \
  --mode personal_identity \
  --scrape 8
```

### Scenario 4: Manual step-by-step investigation

```bash
# 1. Verify Tor
python3 scripts/check_tor.py

# 2. Find alive engines
python3 scripts/check_engines.py

# 3. Search with alive engines
python3 scripts/search.py \
  --query "ransomware hospital 2026" \
  --engines Ahmia Tor66 OSS \
  --max 40

# 4. Fetch top pages
python3 scripts/fetch.py --url "http://..." --links
python3 scripts/fetch.py --url "http://..."

# 5. Analyse
python3 scripts/ask.py \
  --query "hospital ransomware" \
  --mode ransomware \
  --content "combined text from pages"

# 6. Rotate identity when done
python3 scripts/renew.py
```

---

## Analysis modes

### `threat_intel` (default)
General dark web OSINT. Extracts: IoCs, infrastructure details, actor mentions, next investigation steps.

Output sections: Input Query · Source Links · Investigation Artifacts · Key Insights · Recommended Next Steps

### `ransomware`
Malware/RaaS intelligence. Extracts C2 domains, file hashes, MITRE ATT&CK TTPs, victim sectors, ransom amounts.

Output sections: Input Query · Source Links · Malware/Ransomware Indicators · Threat Actor Profile · Key Insights · Recommended Next Steps

### `personal_identity`
PII and breach exposure. Surfaces SSNs, emails, passwords, passport data, breach sources, risk severity ratings.

Output sections: Input Query · Source Links · Exposed PII Artifacts · Breach/Marketplace Sources · Exposure Risk Assessment · Key Insights · Recommended Next Steps

### `corporate`
Corporate threat intelligence. Detects leaked credentials, source code, internal documents, initial access broker activity.

Output sections: Input Query · Source Links · Leaked Corporate Artifacts · Threat Actor/Broker Activity · Business Impact Assessment · Key Insights · Recommended Next Steps

---

## Troubleshooting

**`✗ Tor NOT active`**
```bash
# Is Tor running?
pgrep tor || tor &
# Is port 9050 listening?
ss -tlnp | grep 9050
```

**`renew.py` → `success: false`**
```bash
# Is control port open?
ss -tlnp | grep 9051

# Enable it in torrc:
echo "ControlPort 9051" >> /etc/tor/torrc
echo "CookieAuthentication 1" >> /etc/tor/torrc
systemctl restart tor

# Set correct DataDirectory in .env:
TOR_DATA_DIR=/var/lib/tor      # system Tor (Debian/Ubuntu)
TOR_DATA_DIR=/tmp/tor_data     # custom torrc DataDirectory
```

**`fetch.py` → `status: 0`**
The hidden service is offline. .onion sites go down frequently — try a different URL from `search.py` results. Confirm Tor is healthy with `check_tor.py`.

**`search.py` returns 0 results**
Dark web indexes fluctuate. Run `check_engines.py` to find alive engines, then use `--engines Ahmia Ahmia-clearnet` as reliable fallbacks.

**`ask.py` / `pipeline.py` LLM error**
Set `LLM_PROVIDER` and an API key in `.env`. For no-key local operation: `LLM_PROVIDER=ollama` with a running Ollama instance. All five non-LLM scripts (`check_tor`, `renew`, `check_engines`, `search`, `fetch`) work without any key.

**`ERROR: sicry.py not found`**
`sicry.py` must be in the OnionClaw root (same folder as `SKILL.md`). It is included in this repo — do not delete or move it. If you cloned and it is missing, re-clone fresh.

---

## File structure

```
OnionClaw/
├── SKILL.md              ← OpenClaw skill descriptor (YAML frontmatter)
├── sicry.py              ← SICRY engine (bundled — no separate install needed)
├── .env.example          ← Copy to .env and configure
├── README.md             ← This file
└── scripts/
    ├── check_tor.py      ← Verify Tor / show exit IP
    ├── renew.py          ← Rotate Tor circuit
    ├── check_engines.py  ← Ping all 18 engines
    ├── search.py         ← Search dark web
    ├── fetch.py          ← Fetch .onion pages
    ├── ask.py            ← OSINT analysis via LLM
    └── pipeline.py       ← Full Robin investigation pipeline
```

---

## Credits

- Dark web search engine list and Robin OSINT pipeline from [Robin](https://github.com/apurvsinghgautam/robin) by [@apurvsinghgautam](https://github.com/apurvsinghgautam) — MIT licence
- Core engine: [SICRY](https://github.com/Ps3wb4n/Sicry)
- .onion address verification via [dark.fail](https://dark.fail)
- Agent runtime: [OpenClaw](https://github.com/openclaw/openclaw)
- Network anonymisation: [Tor Project](https://www.torproject.org/)

---
## License

MIT License — Copyright (c) 2026 JacobJandon

"OnionClaw" and the OnionClaw logo are owned by JacobJandon.

See [LICENSE](LICENSE) for full text.

---
> Use responsibly and lawfully. For OSINT, security research, and threat intelligence purposes only.
