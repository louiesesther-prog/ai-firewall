# AI Firewall

[![Test](https://github.com/louiesesther-prog/ai-firewall/actions/workflows/test.yml/badge.svg)](https://github.com/louiesesther-prog/ai-firewall/actions/workflows/test.yml)
[![PII Scan](https://github.com/louiesesther-prog/ai-firewall/actions/workflows/pii-scan.yml/badge.svg)](https://github.com/louiesesther-prog/ai-firewall/actions/workflows/pii-scan.yml)
[![npm version](https://img.shields.io/npm/v/ai-firewall.svg)](https://www.npmjs.com/package/ai-firewall)
[![npm downloads](https://img.shields.io/npm/dm/ai-firewall.svg)](https://www.npmjs.com/package/ai-firewall)
[![License](https://img.shields.io/npm/l/ai-firewall.svg)](https://github.com/louiesesther-prog/ai-firewall/blob/main/LICENSE)
[![Node](https://img.shields.io/node/v/ai-firewall.svg)](https://nodejs.org)

Detect and mask 30+ PII types. 100% local. Web demo, CLI, REST API, Chrome extension, VS Code extension, PWA, and Docker.

## Quick Start

```bash
npx ai-firewall --help
echo "My email is test@example.com" | npx ai-firewall
npx ai-firewall scan .
npx ai-firewall serve    # REST API on :3000
```

## Install

```bash
npm install -g ai-firewall
ai-firewall --help
```

## PII Types (30+)

Email, Phone, SSN, Credit Card (Luhn), IP, Password, API Key, Crypto Wallet, MAC Address, DOB, Passport, Driver License, Street Address, Bank Account, Routing Number, JWT, AWS Key, GitHub Token, Slack Token, UK NI/NHS, India Aadhaar/PAN, China ID, Canada SIN, Australia TFN, Japan My Number, Brazil CPF/CNPJ, France INSEE.

## Platforms

| Platform | Location |
|----------|----------|
| Web Demo | `index.html` (open in browser) |
| CLI | `cli.js` — scan, watch, serve, init, --fix |
| REST API | `server.js` — POST /scrub, POST /scan |
| Chrome Ext | `extension/` — load unpacked |
| VS Code Ext | `.vscode-ext/` — install from VSIX |
| PWA | `sw.js` + `manifest.json` |
| Docker | `docker compose up api` |

## Features

- **PII masking** — 30+ types detected & scrubbed with confidence scoring and Luhn validation
- **Privacy Route (VPN)** — optional secure-tunnel mode reroutes all 19 supported AI-chat sites through your own SOCKS5/HTTPS proxy/VPN endpoint, while every other site stays direct. Bring your own proxy — no servers operated by us.
- **WebRTC / DNS leak protection** — blocks real-IP ICE candidates (allows mDNS only) and forces a non-proxied-UDP WebRTC policy while the tunnel is active
- **100% local** — PII detection and masking never leaves your device

## Test

```bash
npm test    # 232 scenarios, 100% pass rate
```

## Support

If this project helps you, consider supporting development:

| Method | Link |
|--------|------|
| &#9829; GitHub Sponsors | [github.com/sponsors/louiesesther-prog](https://github.com/sponsors/louiesesther-prog) |
| &#9749; Buy Me a Coffee | [buymeacoffee.com/louiesesther-prog](https://buymeacoffee.com/louiesesther-prog) |
| &#11088; Star on GitHub | [github.com/louiesesther-prog/ai-firewall](https://github.com/louiesesther-prog/ai-firewall) |

All support goes toward maintaining the extension, adding new PII types, and improving detection accuracy.

## License

MIT
