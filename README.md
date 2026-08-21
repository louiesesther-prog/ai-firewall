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
node test-report.mjs
# 243/244 tests pass (99.6%)
```

## License

MIT
