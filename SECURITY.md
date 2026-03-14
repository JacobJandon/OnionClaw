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

OnionClaw™ routes all traffic through Tor. Security issues in scope include:
- Traffic leaking outside Tor
- Unsafe handling of untrusted `.onion` page content
- LLM prompt injection via dark web content passed to `ask.py`
- Insecure handling of API keys in `.env`
- Dependency vulnerabilities (`requests`, `stem`, `beautifulsoup4`, `python-dotenv`)
