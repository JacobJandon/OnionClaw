---
name: onionclaw
description: Search the Tor dark web, fetch .onion hidden service pages, rotate Tor identity, and run structured OSINT investigations. Use when user asks to search dark web, investigate .onion sites, find if data appeared on dark web, conduct Tor-based OSINT, look up dark web leaks, fetch any .onion URL, check for leaked credentials, or investigate ransomware groups.
homepage: https://github.com/JacobJandon/OnionClaw
metadata:
  {
    "openclaw": {
      "emoji": "🧅",
      "os": ["darwin", "linux"],
      "requires": {
        "bins": ["python3", "pip3"],
        "pip": ["requests[socks]", "beautifulsoup4", "python-dotenv", "stem"]
      },
      "version": "1.0.0",
      "author": "JacobJandon",
      "license": "Apache-2.0",
      "repo": "https://github.com/JacobJandon/OnionClaw"
    }
  }
---

# OnionClaw — Tor / Dark Web Access

**by JacobJandon** · Apache 2.0 License · [github.com/JacobJandon/OnionClaw](https://github.com/JacobJandon/OnionClaw)

OnionClaw routes all requests through the Tor network. It searches 18 dark web search engines simultaneously, fetches .onion hidden service pages, rotates Tor circuits, and produces structured OSINT reports using the Robin investigation pipeline.

## Setup (run once after install)

Install Python dependencies:
```bash
pip3 install requests[socks] beautifulsoup4 python-dotenv stem
```

Copy and configure `.env`:
```bash
cp {baseDir}/.env.example {baseDir}/.env
# Edit {baseDir}/.env — add LLM_PROVIDER + API key (optional; search and fetch work without one)
```

Before any dark web operation, Tor must be running locally:
```bash
# Linux
apt install tor && tor &

# macOS
brew install tor && tor &
```

---

## Commands

### Check Tor is running

**Always run this first** before any search or fetch.

```bash
python3 {baseDir}/scripts/check_tor.py
```

Output: exit IP address and `tor_active: true/false`. If tor_active is false, tell the user to start Tor and stop.

---

### Rotate Tor identity

Get a fresh exit node and new identity. Use between investigation sessions or when you need a new IP.

```bash
python3 {baseDir}/scripts/renew.py
```

Output: `success: true/false`. If false, the user needs to ensure ControlPort 9051 is enabled and `TOR_DATA_DIR` is set in `.env`.

---

### Search the dark web

Search all 18 dark web engines simultaneously. Returns deduplicated `{title, url, engine}` results.

**Basic search:**
```bash
python3 {baseDir}/scripts/search.py --query "SEARCH_TERM"
```

**With result limit:**
```bash
python3 {baseDir}/scripts/search.py --query "SEARCH_TERM" --max 30
```

**Specific engines only:**
```bash
python3 {baseDir}/scripts/search.py --query "SEARCH_TERM" --engines Ahmia Tor66 Ahmia-clearnet
```

Available engines: Ahmia, OnionLand, Torgle, Amnesia, Kaizer, Anima, Tornado, TorNet, Torland, FindTor, Excavator, Onionway, Tor66, OSS, Torgol, TheDeepSearches, DuckDuckGo-Tor, Ahmia-clearnet

**Tip:** Use short keyword queries (≤5 words). Dark web indexes respond better to focused keywords than natural-language questions.

---

### Fetch a .onion page

Fetch the full content of any .onion URL or clearnet URL through Tor.

```bash
python3 {baseDir}/scripts/fetch.py --url "http://SOME.onion/path"
```

Output: title, text (first 3000 chars), link list, HTTP status. If status is 0 or error is set, the hidden service is unreachable.

---

### Check which search engines are alive

Ping all 18 engines via Tor and get latency + status for each.

```bash
python3 {baseDir}/scripts/check_engines.py
```

Output: per-engine up/down status, latency in ms. Use this before a large search run to pass only alive engines to `--engines`.

---

### OSINT analysis

Analyse scraped dark web content with an LLM. Produces a structured sectioned report.

**From a string:**
```bash
python3 {baseDir}/scripts/ask.py --query "INVESTIGATION_QUERY" --mode MODE --content "RAW_TEXT"
```

**From a file:**
```bash
python3 {baseDir}/scripts/ask.py --query "INVESTIGATION_QUERY" --mode MODE --file /path/to/content.txt
```

**From stdin (pipe):**
```bash
echo "CONTENT" | python3 {baseDir}/scripts/ask.py --query "QUERY" --mode MODE
```

**Analysis modes:**

| Mode | Use for |
|---|---|
| `threat_intel` | General OSINT (default) — artifacts, insights, next steps |
| `ransomware` | Malware/C2/MITRE TTPs, victim orgs, indicators |
| `personal_identity` | PII/breach exposure, severity, protective actions |
| `corporate` | Leaked credentials/code/docs, IR recommendations |

**With custom focus:**
```bash
python3 {baseDir}/scripts/ask.py --query "QUERY" --mode threat_intel --custom "Focus on cryptocurrency wallet addresses"
```

---

### Full OSINT pipeline (one command)

Runs the complete Robin pipeline: refine query → check live engines → search → filter best results → batch scrape → OSINT analysis.

```bash
python3 {baseDir}/scripts/pipeline.py --query "INVESTIGATION_QUERY" --mode MODE
```

**With more results:**
```bash
python3 {baseDir}/scripts/pipeline.py --query "INVESTIGATION_QUERY" --mode ransomware --max 50 --scrape 10
```

**Options:**
- `--query` — investigation topic (natural language OK — it gets refined automatically)
- `--mode` — `threat_intel` (default), `ransomware`, `personal_identity`, `corporate`
- `--max` — max raw results from search (default 30)
- `--scrape` — how many pages to batch-fetch (default 8)
- `--custom` — custom LLM instructions appended to the mode prompt
- `--out FILE` — write final report to a file

---

## Typical investigation flows

### "Search the dark web for X"
1. `python3 {baseDir}/scripts/check_tor.py` — verify connected
2. `python3 {baseDir}/scripts/search.py --query "X"` — search all engines
3. `python3 {baseDir}/scripts/fetch.py --url "URL"` on 2-3 top results
4. `python3 {baseDir}/scripts/ask.py --mode threat_intel --query "X" --content "..."` on combined text

### "Has company.com been leaked on the dark web"
1. `python3 {baseDir}/scripts/check_tor.py`
2. `python3 {baseDir}/scripts/pipeline.py --query "company.com data leak credentials" --mode corporate`
3. Present the structured report to the user

### "Investigate ransomware group X"
1. `python3 {baseDir}/scripts/check_tor.py`
2. `python3 {baseDir}/scripts/pipeline.py --query "GROUP_NAME ransomware" --mode ransomware`

### "Fetch this .onion URL"
1. `python3 {baseDir}/scripts/check_tor.py`
2. `python3 {baseDir}/scripts/fetch.py --url "URL"`
3. Show the user the title + text content

---

## Important notes

- All traffic routes through Tor — tell the user this when relevant.
- .onion sites are frequently offline — if fetch returns `status: 0`, the site is temporarily down.
- Dark web search indexes go down often — run `check_engines.py` first and filter by alive engines.
- LLM tools (`ask`) require an API key in `{baseDir}/.env`. Search and fetch work without any key.
- Use responsibly and lawfully — OSINT, security research, and threat intelligence only.
