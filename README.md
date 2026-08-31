# AI Personal Firewall

Detect and mask 37+ PII types in text before sending to AI chat apps. 100% local processing — nothing leaves your machine.

## Quick Start

### CLI

```bash
# Install
npm install ai-firewall

# Scan text
echo "My email is john@example.com and SSN is 123-45-6789" | npx ai-firewall scan

# Scan a file
npx ai-firewall scan --file document.txt

# Scan with compliance profile
npx ai-firewall scan --profile hipaa --file patient.txt

# Start REST API server
npx ai-firewall serve --port 3000
```

### Install from GitHub Release (no npm account needed)

Download `ai-firewall-<version>.tgz` from the
[Releases page](https://github.com/louiesesther-prog/ai-firewall/releases), then:

```bash
tar -xzf ai-firewall-<version>.tgz
cd package
npm install                 # installs express + sql.js
node cli.js --help          # full CLI
node cli.js license         # open-core tier status (community by default)
node server.js              # self-host the REST API
```

The tarball includes the CLI, REST server, browser extensions, and (with a valid
license key) all enterprise modules — SSO/SCIM, RBAC, multi-tenancy, policy
engine, alerts, shadow mode, network agent, reporting, and marketplace.

### Docker

```bash
docker build -t ai-firewall .
docker run --rm ai-firewall --help
# self-hosted server on port 3000:
docker run --rm -p 3000:3000 -e ENTERPRISE_ALL=1 ai-firewall serve
```

### Browser Extension

Available for Chrome, Edge, Firefox, and Safari:

- **Chrome/Edge**: Load `extension/` or `edge/` as unpacked extension
- **Firefox**: Load `firefox/` as temporary add-on
- **Safari**: Use `safari/` with Xcode

Features:
- Real-time PII detection in chat input fields
- Auto-masking on Enter key
- Undo with Ctrl+Z
- Highlight overlay with type-specific colors
- Sound notification on detection
- Response/output PII scanning
- Per-site enable/disable
- VPN/proxy routing with WebRTC leak protection

### VS Code Extension

```bash
# Install from .vscode-ext folder
# 1. Open VS Code
# 2. Ctrl+Shift+P → "Extensions: Install from VSIX..."
# 3. Select .vscode-ext/package.json

# Or copy .vscode-ext/ to ~/.vscode/extensions/ai-firewall/
```

Features:
- Inline diagnostics (squiggly lines) on PII
- Scan-on-save
- Compliance profiles (GDPR, HIPAA, CCPA, PCI-DSS, SOX)
- Per-document undo (Ctrl+Z)

### PWA (Web App)

Open `index.html` in a browser or serve with `npx ai-firewall serve`:

- Paste text → instant PII detection
- Encrypt/Decrypt with password
- Compliance profiles
- Works offline (service worker)

### Docker

```bash
docker build -t ai-firewall .
docker run -p 3000:3000 ai-firewall

# With document scanning support
docker run -p 3000:3000 -v ./documents:/app/documents ai-firewall
```

### Slack/Discord Bot

```bash
# Copy and configure
cp bot/config.example.json bot/config.json
# Edit bot/config.json with your tokens

# Start Slack bot
node bot/slack.cjs

# Start Discord bot
node bot/discord.cjs
```

Commands:
- `/scrub <text>` or `!scrub <text>` — Mask PII
- `/scan <text>` or `!pii <text>` — Detect PII (no masking)
- `/help` or `!help` — Show commands

## API Reference

### `POST /scan`

```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "My email is john@example.com"}'
```

Response:
```json
{
  "masked": "My email is [EMAIL_ADDR_1]",
  "matches": [{"type": "EMAIL_ADDR", "original": "john@example.com", "placeholder": "[EMAIL_ADDR_1]", "confidence": 0.95}],
  "count": 1
}
```

### `POST /scan-file`

```bash
curl -X POST http://localhost:3000/scan-file \
  -H "X-API-Key: your-api-key" \
  -F "file=@document.txt"
```

Supports `.txt`, `.docx`, `.pdf`, `.png`, `.jpg`

### `GET /analytics`

Dashboard with real-time PII detection analytics (requires `better-sqlite3`).

## PII Types Detected (37)

| Category | Types |
|----------|-------|
| **Identity** | SSN, Passport, Driver License, Date of Birth |
| **Financial** | Credit Card (Luhn), Bank Account, Routing Number |
| **Contact** | Email, Phone, Street Address |
| **International** | UK NI/NHS, India Aadhaar/PAN, China ID, Canada SIN, Australia TFN, Japan My Number, Brazil CPF/CNPJ, France INSEE, Germany ID/Tax, Korea RRN, Mexico CURP/RFC, Sweden Personnummer, Italy Codice Fiscale |
| **Credentials** | API Key, Password, JWT, AWS Key, GitHub Token, Slack Token |
| **Network** | IP Address (octet-validated), MAC Address, Crypto Wallet |

## Compliance Profiles

| Profile | PII Types |
|---------|-----------|
| `gdpr` | EU personal data |
| `hipaa` | Health-related PII |
| `ccpa` | California consumer data |
| `pci-dss` | Payment card data |
| `sox` | Financial reporting data |

## Configuration

### CLI Flags

| Flag | Description |
|------|-------------|
| `--mode <type>` | Masking mode: `placeholder` (default) or `realistic` |
| `--profile <name>` | Compliance profile filter |
| `--format <type>` | Output format: `text`, `json`, `csv` |
| `--dry-run` | Show what would be masked without modifying |
| `--progress` | Show progress bar for large files |
| `--unsafe` | Allow string-based custom fakers (uses `new Function()`) |
| `--summary` | Show summary statistics |
| `--output <file>` | Write output to file |
| `--ci` | CI mode with exit codes |

### API Server Options

```bash
npx ai-firewall serve \
  --port 3000 \
  --host 0.0.0.0 \
  --api-key your-secret-key \
  --cors "https://yourapp.com" \
  --rate-limit 100
```

## Optional Dependencies

| Package | Purpose |
|---------|---------|
| `pdf-parse` | PDF document scanning |
| `better-sqlite3` | Analytics dashboard |
| `@slack/bolt` | Slack bot |
| `discord.js` | Discord bot |

```bash
npm install ai-firewall pdf-parse better-sqlite3 @slack/bolt discord.js
```

## Architecture

```
ai-firewall/
├── cli.js              # Main CLI entry point
├── server.js           # REST API server
├── rules.cjs           # Canonical PII rules (37 types)
├── context.cjs         # Context-aware detection engine
├── scanners/           # Document format parsers
│   ├── index.cjs       # Format dispatcher
│   ├── docx.cjs        # DOCX parser
│   ├── pdf.cjs         # PDF scanner
│   └── ocr.cjs         # Image OCR
├── analytics/          # Usage analytics
│   ├── db.cjs          # SQLite schema
│   ├── tracker.cjs     # Event recording
│   ├── queries.cjs     # Dashboard queries
│   └── dashboard.html  # SVG chart UI
├── enterprise/         # Enterprise features (Phases 2–5)
│   ├── feature-flags.cjs  # Per-module flag resolution
│   ├── routes/            # REST route factories per module
│   ├── dashboard/         # /enterprise admin web UI
│   ├── identity/          # SSO, SCIM
│   ├── policy/            # Policy engine
│   ├── observability/     # Shadow mode, network agent
│   ├── auth/              # API keys, RBAC, teams
│   ├── tenancy/           # Organizations
│   ├── billing/           # Quotas, scheduled reports
│   ├── alerts/            # Alerts, webhooks
│   ├── reporting/         # Advanced reporting
│   └── marketplace/       # Policy packs & templates
├── bot/                # Chat bots
│   ├── core.cjs        # Platform-agnostic logic
│   ├── slack.cjs       # Slack adapter
│   └── discord.cjs     # Discord adapter
├── extension/          # Chrome extension
├── edge/               # Edge extension
├── firefox/            # Firefox extension
├── safari/             # Safari extension
├── .vscode-ext/        # VS Code extension
├── index.html          # PWA web app
├── sw.js               # Service worker
├── sync-rules.js       # Rules sync script
└── test-report.mjs     # Test suite (244 tests)
```

## Testing

```bash
node test-report.mjs          # core suite: 242/244 pass (99.2%)
node test-enterprise.mjs      # enterprise suite: 46/46 pass
```

The two "failed" core checks are intentional stricter/strictness cases (`FP20` international
phone-format gap, `FP25` stricter passport rule), not regressions.

## Enterprise (Phases 2–5)

Enterprise features are gated behind `better-sqlite3` plus feature flags. Each module is
mounted only when its flag is enabled, and they are exposed through the REST API and the
web dashboard at `/enterprise`.

### Feature flags

Set `ENTERPRISE_ALL=1` to enable everything, or toggle modules individually via the env
vars below (explicit flags win over `ENTERPRISE_ALL`; `0`/`false`/`no`/`off`/`` disable a flag).

| Flag | Feature |
|------|---------|
| `ENTERPRISE_ALL` | Master switch for all enterprise modules |
| `ENTERPRISE_API_KEYS` | API key management & per-key quotas |
| `ENTERPRISE_TEAMS` | Team management |
| `ENTERPRISE_QUOTAS` | Plan/usage quotas |
| `ENTERPRISE_SCHEDULED` | Scheduled reports |
| `ENTERPRISE_SSO` | SSO sign-in |
| `ENTERPRISE_SCIM` | SCIM user provisioning |
| `ENTERPRISE_POLICY` | Policy engine (data guardrails) |
| `ENTERPRISE_ALERTS` | Alert subscriptions/notifications |
| `ENTERPRISE_WEBHOOKS` | Outbound webhooks |
| `ENTERPRISE_GUARDRAILS` | Prompt/data guardrails |
| `ENTERPRISE_SHADOW` | Shadow-mode AI service detection |
| `ENTERPRISE_RESPONSE_SCAN` | Outbound response scanning |
| `ENTERPRISE_NETWORK_AGENT` | Network agent observability |
| `ENTERPRISE_RBAC` | Role-based access control |
| `ENTERPRISE_TENANCY` | Multi-tenant organizations |
| `ENTERPRISE_REPORTING` | Advanced/analytics reporting |
| `ENTERPRISE_MARKETPLACE` | Policy packs & templates marketplace |

Other enterprise options: `AIFW_DB_PATH` (SQLite file for analytics),
`AIFW_SSO_SIGNING_KEY` (HMAC key for SSO tokens; defaults to a stable internal hash).

### Run with enterprise enabled

```bash
npm install better-sqlite3          # native module required for enterprise features
ENTERPRISE_ALL=1 node server.js     # live API + /enterprise dashboard
```

### Enterprise modules

- **Identity** — SSO (`sso`), SCIM provisioning (`scim`)
- **Policy** — data-guardrail policy engine (`policy-engine`)
- **Observability** — shadow-mode AI detection (`shadow-mode`), network agent (`network-agent`)
- **Access** — API keys (`api-keys`), RBAC (`rbac`), teams (`teams`), organizations/tenancy (`organizations`)
- **Billing/ops** — quotas (`quotas`), scheduled reports (`scheduled-reports`), alerts (`alerts`), webhooks (`webhooks`)
- **Reporting** — advanced/analytics reporting (`advanced-reporting`)
- **Marketplace** — policy packs & templates (`marketplace`)
- **Dashboard** — single-page admin UI at `/enterprise` (API Keys, Quotas, Audits, Webhooks,
  Teams, Scheduled, SSO, SCIM, Policies, Alerts, Shadow, Network, Orgs, RBAC, Analytics, Marketplace)

Run `node cli.js enterprise` for CLI subcommands over the same modules.

## License

MIT
