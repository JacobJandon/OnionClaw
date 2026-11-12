# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes     |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub private vulnerability reporting](https://github.com/JacobJandon/OnionClaw/security/advisories/new) or contact the owner via the [GitHub profile](https://github.com/JacobJandon).

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours. Please allow time to patch before public disclosure.

## Scope

Searches, page fetches, crawls, onion-page monitoring and update checks go through Tor,
and are skipped rather than sent directly when Tor is not running. Three kinds of traffic
are deliberately direct, and you should know which:

- **LLM analysis** (`ask.py`, the pipeline's analysis steps, `swarm.py --llm`) sends your
  query and the scraped content to the provider you configure. Use a local model
  (`LLM_PROVIDER=ollama` or `llamacpp`) to keep it on your machine.
- **The swarm's clearnet collectors** fetch public feeds from ransomware.live, CISA KEV and
  mempool.space directly. Wallet lookups therefore show mempool.space which addresses you
  are interested in.
- **`sync_sicry.py`**, a maintenance tool, downloads the engine from GitHub directly.

Security issues in scope include:
- Traffic leaking outside Tor
- Unsafe handling of untrusted `.onion` page content
- LLM prompt injection via dark web content passed to `ask.py`
- Insecure handling of API keys in `.env`
- Dependency vulnerabilities (`requests`, `stem`, `beautifulsoup4`, `python-dotenv`)
