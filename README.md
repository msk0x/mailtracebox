<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

<h1 align="center">MailTraceBox</h1>

<p align="center">Production-grade Email Intelligence Framework for authorized OSINT collection.</p>

---

## Overview

MailTraceBox takes an email address and runs 11 intelligence plugins concurrently to build a full digital footprint. Built on asyncio and aiohttp for high-performance network I/O with a plugin-based architecture that is fully extensible.

## Features

- Plugin-based architecture with 11 built-in intelligence sources
- Fully asynchronous — all platform checks run concurrently
- Three-phase account discovery: email search, username sweep, variant sweep
- Smart username variant generation from email local parts
- Multiple output formats: Rich terminal, JSON, HTML, Markdown, CSV
- Configurable rate limiting with token-bucket algorithm
- TTL caching for repeated scans
- Retry logic with exponential backoff
- YAML config with environment variable and CLI overrides

## Plugins

- **account_discovery** — Discovers accounts across 40+ platforms using email and username lookups
- **breach_check** — Checks email against known data breaches via Have I Been Pwned
- **dns_recon** — Resolves MX, SPF, DMARC, A, and NS records
- **email_validator** — Validates format, detects disposable and role accounts
- **gravatar** — Looks up Gravatar profile and avatar
- **http_headers** — Analyzes security headers and fingerprints technology stack
- **ip_info** — Geolocates mail server IP addresses
- **smtp_verify** — Verifies SMTP deliverability via RCPT TO probing
- **social_check** — Detects social media profile pages
- **crtsh** — Enumerates subdomains through TLS certificate transparency logs
- **whois_lookup** — Retrieves domain WHOIS registration data

## Installation

### Quick Install

```bash
git clone https://github.com/msk0x/MailTraceBox.git
cd MailTraceBox
make install
MailTraceBox scan user@example.com
```

This uses [pipx](https://pipx.pypa.io/) to install in an isolated environment. No venv activation needed.

### Manual Install (pipx)

```bash
git clone https://github.com/msk0x/MailTraceBox.git
cd MailTraceBox
pipx install -e .
MailTraceBox scan user@example.com
```

### Manual Install (venv)

```bash
git clone https://github.com/msk0x/MailTraceBox.git
cd MailTraceBox
python3 -m venv .venv
source .venv/bin/activate
pip install -e "."
MailTraceBox scan user@example.com
```

For development with testing and linting tools:

```bash
make install-dev
source .venv/bin/activate
```

Requires Python 3.11 or higher.

## Usage

```bash
# Full scan with all plugins
MailTraceBox scan user@example.com

# Run specific plugins
MailTraceBox scan user@example.com --plugins account_discovery,breach_check

# JSON output
MailTraceBox scan user@example.com --output json --output-file report.json

# HTML output
MailTraceBox scan user@example.com --output html --output-file report.html

# Custom config
MailTraceBox scan user@example.com --config config/local.yml

# Debug mode
MailTraceBox scan user@example.com -d

# List plugins
MailTraceBox plugins list

# Show config
MailTraceBox config show
```

## GitHub Token

The account discovery plugin checks GitHub with or without authentication. A token raises the rate limit from 60 to 5,000 requests per hour.

```bash
cat > config/local.yml << 'EOF'
api_keys:
  GITHUB_TOKEN: "ghp_your_token_here"
EOF
```

Generate a token at GitHub Settings under Developer Settings and Personal Access Tokens. No scopes required. The `config/local.yml` file is gitignored by default.

## Configuration

Priority order: CLI arguments, then environment variables, then YAML file, then built-in defaults.

Environment variables use the `MAILTRACEBOX_` prefix:

```bash
export MAILTRACEBOX_HTTP_TIMEOUT=15
export MAILTRACEBOX_HTTP_RATE_LIMIT_REQUESTS=120
export MAILTRACEBOX_LOGGING_LEVEL=DEBUG
```

## Writing Plugins

Drop a Python file into `src/MailTraceBox/plugins/`. Plugins are auto-discovered.

```python
from MailTraceBox.plugins.base import BasePlugin
from MailTraceBox.models.plugin import PluginResult, PluginStatus

class MyPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "my_plugin"

    @property
    def description(self) -> str:
        return "Custom intelligence source."

    @property
    def version(self) -> str:
        return "1.0.0"

    async def execute(self, context, http_client, config):
        resp = await http_client.get(f"https://api.example.com/{context.target_email}")
        if resp.ok:
            data = resp.json()
        return PluginResult(plugin_name=self.name, status=PluginStatus.COMPLETED)
```

## Development

```bash
pytest tests/ -v
pytest tests/ --cov=MailTraceBox --cov-report=term-missing
ruff check src/ tests/
mypy src/MailTraceBox
```

## Security

This tool is designed for authorized intelligence collection only. It uses publicly accessible information and documented APIs, never authenticates into third-party accounts, and never bypasses CAPTCHAs or access controls. Use only on targets you are authorized to investigate.

## License

MIT License. See LICENSE for details.
