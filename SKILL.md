---
name: onionclaw
description: Search the Tor dark web, fetch and crawl .onion hidden service pages, rotate Tor identity, run structured OSINT investigations, and monitor ransomware leak sites for changes. Use when user asks to search dark web, investigate .onion sites, find if data appeared on dark web, conduct Tor-based OSINT, look up dark web leaks, fetch or crawl any .onion URL, check for leaked credentials, investigate, monitor or prioritise ransomware groups, map them to MITRE ATT&CK, pull a list of indicators (onion hosts, domains, wallets, CVEs) to block, watch for new victims in a sector, or export threat intel as STIX 2.1.
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
      "version": "2.4.0",
      "author": "JacobJandon",
      "license": "Apache-2.0",
      "repo": "https://github.com/JacobJandon/OnionClaw"
    }
  }
---

# OnionClaw — Tor / Dark Web Access

**by JacobJandon** · Apache License 2.0 · [github.com/JacobJandon/OnionClaw](https://github.com/JacobJandon/OnionClaw)

OnionClaw routes all requests through the Tor network. It searches 17 dark web search engines simultaneously, fetches .onion hidden service pages, rotates Tor circuits, and produces structured OSINT reports using the Robin investigation pipeline.

## Setup (run once after install)

Install Python dependencies:
```bash
pip3 install requests[socks] beautifulsoup4 python-dotenv stem
```

Run the interactive first-run wizard (sets up `.env` and torrc in one step):
```bash
python3 {baseDir}/setup.py
```

Or set up manually:
```bash
cp {baseDir}/.env.example {baseDir}/.env
# Edit {baseDir}/.env — add LLM_PROVIDER + API key (optional; search and fetch work without one)
```

Start Tor (required before any command):
```bash
# Linux:  sudo apt install tor && sudo systemctl start tor
# macOS:  brew install tor && brew services start tor
# Custom: tor -f /tmp/tor_data/torrc &   (setup.py creates this)
```

Enable circuit rotation (ControlPort) — required for `renew.py`:
```
Add to /etc/tor/torrc:
  ControlPort 9051
  CookieAuthentication 1
Then restart Tor.  setup.py does this automatically.
```

---

## Commands

### Check Tor is running

**Always run this first** before any search or fetch.

```bash
python3 {baseDir}/check_tor.py
```

Output: exit IP address and `tor_active: true/false`. If tor_active is false, tell the user to start Tor and stop.

---

### Rotate Tor identity

Get a fresh exit node and new identity. Use between investigation sessions or when you need a new IP.

```bash
python3 {baseDir}/renew.py
```

Output: `success: true/false`. If false, the user needs to ensure ControlPort 9051 is enabled and `TOR_DATA_DIR` is set in `.env`.

---

### Search the dark web

Search all 17 dark web engines simultaneously. Returns deduplicated `{title, url, engine}` results.

**Basic search:**
```bash
python3 {baseDir}/search.py --query "SEARCH_TERM"
```

**With result limit:**
```bash
python3 {baseDir}/search.py --query "SEARCH_TERM" --max 30
```

**Specific engines only:**
```bash
python3 {baseDir}/search.py --query "SEARCH_TERM" --engines Ahmia Tor66 Ahmia-clearnet
```

Available engines: Ahmia, OnionLand, Amnesia, Torland, Excavator, Onionway, Tor66, OSS, Torgol, TheDeepSearches, DuckDuckGo-Tor, Ahmia-clearnet

**Tip:** Use short keyword queries (≤5 words). Dark web indexes respond better to focused keywords than natural-language questions.

---

### Fetch a .onion page

Fetch the full content of any .onion URL or clearnet URL through Tor.

```bash
python3 {baseDir}/fetch.py --url "http://SOME.onion/path"
```

Output: title, text (first 3000 chars), link list, HTTP status. If status is 0 or error is set, the hidden service is unreachable.

---

### Check which search engines are alive

Ping all 12 engines via Tor and get latency + status for each.

```bash
python3 {baseDir}/check_engines.py
```

Output: per-engine up/down status, latency in ms. Use this before a large search run to pass only alive engines to `--engines`.

---

### OSINT analysis

Analyse scraped dark web content with an LLM. Produces a structured sectioned report.

**From a string:**
```bash
python3 {baseDir}/ask.py --query "INVESTIGATION_QUERY" --mode MODE --content "RAW_TEXT"
```

**From a file:**
```bash
python3 {baseDir}/ask.py --query "INVESTIGATION_QUERY" --mode MODE --file /path/to/content.txt
```

**From stdin (pipe):**
```bash
echo "CONTENT" | python3 {baseDir}/ask.py --query "QUERY" --mode MODE
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
python3 {baseDir}/ask.py --query "QUERY" --mode threat_intel --custom "Focus on cryptocurrency wallet addresses"
```

---

### Full OSINT pipeline (one command)

Runs the complete Robin pipeline: refine query → check live engines → search → filter best results → batch scrape → OSINT analysis.

```bash
python3 {baseDir}/pipeline.py --query "INVESTIGATION_QUERY" --mode MODE
```

**With more results:**
```bash
python3 {baseDir}/pipeline.py --query "INVESTIGATION_QUERY" --mode ransomware --max 50 --scrape 10
```

**Without an LLM key (raw results only):**
```bash
python3 {baseDir}/pipeline.py --query "INVESTIGATION_QUERY" --no-llm
```

**Options:**
- `--query` — investigation topic (natural language OK — it gets refined automatically)
- `--mode` — `threat_intel` (default), `ransomware`, `personal_identity`, `corporate`
- `--max` — max raw results from search (default 30)
- `--scrape` — how many pages to batch-fetch (default 8)
- `--custom` — custom LLM instructions appended to the mode prompt
- `--out FILE` — write final report to a file
- `--no-llm` — skip refine/filter/ask steps; dump raw scraped content (no API key needed)

---

### Crawl one hidden service

Follow links within a single .onion site and collect checksum-validated entities (BTC/ETH/XMR wallets, emails, .onion links, Tox IDs, PGP blocks). Pages in a level are fetched concurrently.

```bash
python3 {baseDir}/crawl.py --url "http://example.onion" --depth 2 --max-pages 15
python3 {baseDir}/crawl.py --url "http://example.onion" --json
```

Abuse material is never crawled; every refusal is listed with its reason in the output.

---

### Monitor for changes (swarm)

Read-only collectors run in parallel and report only what changed since the last sweep. State is kept in `{baseDir}/onionclaw.db`; the first run records a quiet baseline.

```bash
python3 {baseDir}/swarm.py                                  # one sweep → prioritised digest
python3 {baseDir}/swarm.py --watch healthcare --watch US    # flag matching events as PRIORITY
python3 {baseDir}/swarm.py --wallet bc1q...                 # track a Bitcoin address on-chain
python3 {baseDir}/swarm.py --onion http://xyz.onion         # watch a hidden-service page (needs Tor)
python3 {baseDir}/swarm.py --json                           # machine-readable digest
```

Collectors: `leaksites` (ransomware.live victims), `groupinfra` (leak-site up/down), `kev` (CISA KEV, incl. CVEs newly tied to ransomware), `wallets` (mempool.space), `onionsites` (your URLs via Tor). Clearnet sources work without Tor.

Alerts: `--webhook URL --webhook-format slack|discord|generic` (exactly-once per webhook, optional `--webhook-secret` HMAC signing).

---

### Export STIX 2.1 and correlate groups

```bash
python3 {baseDir}/stix.py -o bundle.json          # STIX 2.1 bundle for MISP / OpenCTI
python3 {baseDir}/graph.py                         # groups linked by shared wallet / host / alias, with evidence
python3 {baseDir}/graph.py --activity              # groups ranked by time-decayed activity
```

Correlation is a lead for an analyst, not attribution — present the evidence with every link.

---

### Prioritise groups and map their ATT&CK techniques

```bash
python3 {baseDir}/risk.py                         # groups ranked by a transparent priority score
python3 {baseDir}/risk.py --group qilin           # every factor behind one group's score
python3 {baseDir}/ttp.py --group medusa           # MITRE ATT&CK techniques + tools for a group
python3 {baseDir}/ttp.py --technique T1078        # which observed groups use a technique
python3 {baseDir}/ttp.py                          # most-used techniques across observed groups
```

### List every observed indicator

```bash
python3 {baseDir}/iocs.py                              # all indicators, most actionable first
python3 {baseDir}/iocs.py --group qilin                # indicators attributed to one group
python3 {baseDir}/iocs.py --type btc_wallet --type cve
python3 {baseDir}/iocs.py --flag ransomware            # KEV CVEs tied to ransomware campaigns
python3 {baseDir}/iocs.py --format csv -o iocs.csv     # table | json | csv
```

Types: `onion_host`, `domain`, `btc_wallet`, `cve`, `email`, `tox`. The list is derived from
stored observations, so it never disagrees with them. Values are **defanged** by default
(`hxxp://`, `[.]`) for safe sharing; pass `--fanged` for machine-readable output. Attribution
comes from what a leak site published, not analysis — present it as a lead.

---

`ttp.py` uses the ATT&CK data ransomware.live publishes per group (confidence "high") and adds whole-word keyword hits from ransom notes (confidence "low", each with the sentence it came from). `risk.py` scores volume, critical-sector victims, reach, capability and evidence links, then decays groups that have gone quiet. Present the score as a triage order, not a threat verdict, and show the factors.

---

## Typical investigation flows

### "Search the dark web for X"
1. `python3 {baseDir}/check_tor.py` — verify connected
2. `python3 {baseDir}/search.py --query "X"` — search all engines
3. `python3 {baseDir}/fetch.py --url "URL"` on 2-3 top results
4. `python3 {baseDir}/ask.py --mode threat_intel --query "X" --content "..."` on combined text

### "Has company.com been leaked on the dark web"
1. `python3 {baseDir}/check_tor.py`
2. `python3 {baseDir}/pipeline.py --query "company.com data leak credentials" --mode corporate`
3. Present the structured report to the user

### "Investigate ransomware group X"
1. `python3 {baseDir}/check_tor.py`
2. `python3 {baseDir}/pipeline.py --query "GROUP_NAME ransomware" --mode ransomware`

### "Watch for new ransomware victims in sector X"
1. `python3 {baseDir}/swarm.py --watch "X"` — the first run baselines; later runs report only changes
2. Present the PRIORITY events first, then the rest of the digest

### "Give me indicators for group X we can block"
1. `python3 {baseDir}/swarm.py` — refresh observations
2. `python3 {baseDir}/iocs.py --group X --fanged --format csv -o X.csv`
3. Note which rows are flagged `live`; say plainly that attribution is the leak site's claim

### "Which ransomware groups should we worry about right now?"
1. `python3 {baseDir}/swarm.py` — refresh observations
2. `python3 {baseDir}/risk.py` — ranked list; then `risk.py --group NAME` for the top ones
3. `python3 {baseDir}/ttp.py --group NAME` — the ATT&CK techniques to defend against

### "Fetch this .onion URL"
1. `python3 {baseDir}/check_tor.py`
2. `python3 {baseDir}/fetch.py --url "URL"`
3. Show the user the title + text content

---

## Important notes

- All traffic routes through Tor — tell the user this when relevant.
- .onion sites are frequently offline — if fetch returns `status: 0`, the site is temporarily down.
- Dark web search indexes go down often — run `check_engines.py` first and filter by alive engines.
- LLM tools (`ask`) require an API key in `{baseDir}/.env`. Search and fetch work without any key.
- The swarm's collectors only read public data; never use OnionClaw to contact, negotiate with, or deceive anyone.
- ransomware.live's free API is for personal use and allows 1 request/minute per endpoint; OnionClaw enforces the limit. Business use needs a PRO key (`RANSOMWARE_LIVE_API_KEY`).
- Use responsibly and lawfully — OSINT, security research, and threat intelligence only.

---

## Maintenance

### sync_sicry.py — update bundled sicry.py from upstream

`sync_sicry.py` fetches the latest (or a tagged) `sicry.py` from the upstream
[SICRY™ GitHub repo](https://github.com/JacobJandon/Sicry) and overwrites the
bundled copy inside OnionClaw. Run it after a new SICRY™ release is published.

### Checking for OnionClaw updates

OnionClaw will **automatically notify you** whenever a newer release is
available — a one-line message is printed at startup of `pipeline.py` if an
update exists. You can also check on demand:

```bash
# Quick CLI update check (prints latest version, release URL, upgrade command):
python3 {baseDir}/pipeline.py --check-update

# Programmatic check from any Python environment:
import sicry
r = sicry.check_update()
if not r["up_to_date"]:
    print(f"Update: {r['current']} → {r['latest']}  {r['url']}")
```

Upgrade after a new release:

```bash
git -C {baseDir} pull                          # update the whole repo
python3 {baseDir}/sync_sicry.py               # re-sync sicry.py from SICRY™
```

The check is clearnet-only (not through Tor), uses a 4-second timeout, and
is always silent on network errors.

```bash
# Pull latest main branch:
python3 {baseDir}/sync_sicry.py

# Pull a specific release tag:
python3 {baseDir}/sync_sicry.py --tag v1.2.0

# Preview without writing (dry run):
python3 {baseDir}/sync_sicry.py --dry-run
```

**Development workflow** (when editing sicry.py locally):
1. Edit `OnionClaw/sicry.py`.
2. Copy to parent repo: `cp OnionClaw/sicry.py Sicry/sicry.py`
3. Commit + tag both repos, then push.
4. Once the tag is live on GitHub, users can run `sync_sicry.py --tag vX.Y.Z`
   to update their OnionClaw copy.

Flags:
- `--tag REF`   — git ref or tag to fetch (default: `main`)
- `--dry-run`   — show what would happen without writing anything
