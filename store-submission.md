# Chrome Web Store — Submission Packet

Complete submission guide for `AI Personal Firewall` v2.1.1 (Chrome + Brave + Vivaldi + Opera).

> Package to upload: `dist/ai-firewall-chrome.zip` (already store-ready, PNG icons, validated).
> Privacy policy URL: `https://ai-firewall.org/privacy.html` (live and verified).

---

## 0. Pre-requisites (do once)

1. **Google Account with 2-Step Verification enabled** (mandatory since 2022 — no 2SV, no publishing).
2. **Register developer account**: https://chrome.google.com/webstore/devconsole → pay **$5 one-time fee**.
3. **Verify your email + a phone number** on the account.
4. **Declare trader/non-trader status** (EU requirement) — pick "Non-trader" unless you're a registered business.
5. (Optional) Set up **GitHub Actions auto-upload** later via the API path described in §6.

---

## 1. Upload the Package

1. Go to https://chrome.google.com/webstore/devconsole
2. Sign in → **Add new item** (top-right).
3. **Choose file** → `dist/ai-firewall-chrome.zip`
4. Click **Upload** → it validates the manifest and shows your item.

> If you changed nothing since the last release, later updates upload the same file — version must increase each time (we're at 2.1.1).

---

## 2. Store Listing tab — copy-paste this

### Name
```
AI Personal Firewall
```

### Short description (≤132 chars) — paste exactly
```
Masks 30+ PII types in AI chats. 100% local. Luhn-validated CC, confidence scoring. Protects ChatGPT, Claude, Gemini, Copilot.
```

### Detailed description — paste exactly

```
# AI Personal Firewall

Keep your sensitive data private when using AI chat applications.

AI Personal Firewall automatically detects and masks Personally Identifiable Information (PII) in your prompts before they reach AI providers. Processing is 100% local — your data never leaves your browser.

## What it does

AI Personal Firewall is a single-purpose privacy extension: it scrubs sensitive text from your AI chat prompts before any provider sees it, and restores the original values after the AI responds. It does nothing else.

## Features

- 30+ PII types detected — email, phone, SSN, credit cards, IP addresses, crypto wallets, passwords, API keys, MAC addresses, DOB, passport numbers, driver licenses, street addresses, bank accounts, routing numbers, JWT tokens, AWS keys, GitHub tokens, Slack tokens, and more
- 10 international PII types — UK National Insurance and NHS, India Aadhaar and PAN, China 18-digit ID, Canada SIN, Australia TFN, Japan My Number, Brazil CPF and CNPJ, France INSEE
- Luhn checksum validation — distinguishes real credit card numbers from random digits
- Confidence scoring — every detection includes a 0.0-1.0 confidence score
- Smart context heuristics — reduces false positives from version numbers, math, product codes
- Realistic fake-data masking — optional, replaces PII with realistic fake values
- Auto-restore — AI responses have placeholders restored to original values transparently
- Privacy dashboard — scrubbing stats, PII type breakdown, detection history
- Toggle protection on and off in one click

## Works with

ChatGPT, Copilot, Gemini, Claude, Perplexity, Poe, Groq, Mistral, Cohere, Meta AI, DeepSeek, You.com, Kimi, Qwen, Jina, Phind, and Google AI Chat — 17 platforms.

## Secure and open source

- 100% local processing — all detection and masking happens in your browser
- No servers, no analytics, no logging — this extension makes no network requests of its own
- MIT licensed, full source on GitHub

## Optionally available separately

A fully optional, off-by-default proxy routing feature ("Privacy Route") is included for users who want to route AI-site traffic through their own proxy endpoint. It is disabled by default and stores your settings only on your device. We operate no proxies or VPN servers.
```

### Category
- **Primary category:** Productivity
- **Secondary category (optional):** Privacy & Security

### Language
`English`

### Search terms (tags) — paste into the tags field
```
privacy, PII, AI, ChatGPT, Claude, Gemini, Copilot, security, data protection, masking, scrub, redact, confidential, GDPR, HIPAA, PCI-DSS, open source
```

### Upload these images (all ready in `store-images/`)

| Field | File | Size |
|---|---|---|
| Store icon | `extension/icons/icon128.png` | 128×128 PNG |
| Screenshot 1 | `store-images/screenshot-1-dashboard.png` | 1280×800 |
| Screenshot 2 | `store-images/screenshot-2-detection.png` | 1280×800 |
| Screenshot 3 | `store-images/screenshot-3-stats.png` | 1280×800 |
| Small promo tile | `store-images/small-promo.png` | 440×280 |
| Marquee promo (optional) | `store-images/marquee-promo.png` | 1400×560 |

### Homepage URL
```
https://ai-firewall.org
```

### Support URL
```
https://ai-firewall.org/support.html
```

---

## 3. Privacy tab — answer these exactly

### Single purpose description (one sentence)
```
Scrubs personally identifiable information from AI chat prompts locally in the browser before they are sent to AI providers, and restores original values in the AI response.
```

### User data collection disclosures
This extension collects **no data** from users. Set the disclosure level to:

> **"Does not transmit or sell user data. Uses only locally processed data."**

Fill the "user data" question with **"No"** for user-triggered collection, background collection, and remote code. You'll certify the Limited Use statement:

- [x] I do not sell user data
- [x] I do not use or transfer user data for purposes unrelated to the extension's single purpose
- [x] I do not use or transfer user data to determine creditworthiness or for lending purposes

### Privacy policy URL
```
https://ai-firewall.org/privacy.html
```
(Required because the extension processes user text — the URL is live, HTTPS, and public.)

### Permissions justification
The dashboard shows a warning for `webRequestBlocking` + `<all_urls>`. **This is expected** — you must write a justification. Paste this into the reviewer notes field:

```
1. storage — saves on/off toggle state and rolling usage statistics (requests scrubbed, PII count per type) to the browser's local extension storage. Nothing is transmitted.
2. cookies — used by the optional cookie-blocking feature to strip third-party cookies from supported AI chat domains when the user enables it in the popup. It is off by default.
3. proxy — used only by the optional Privacy Route feature, which is disabled by default. When enabled, it routes traffic to supported AI-chat domains through a proxy endpoint the user supplies themselves. We operate no proxy servers.
4. privacy — used only while Privacy Route is active, to enforce stricter WebRTC IP-handling for leak protection. Inactive by default.
5. scripting — used to attach the PII detection/replace listener to chat input fields on supported AI chat pages.
6. webRequest + webRequestBlocking — used by the optional cookie-blocking feature to strip cookies from AI chat requests/responses when the user opts in. All logic runs locally; no request content is captured or sent anywhere.
7. <all_urls> host permission — restricted in code to the 17 supported AI chat domains via the manifest content_scripts "matches" list; the host permission additionally covers these same domains for the background service worker. The extension does not operate, collect, or transmit on any other site.

Note: every intrusive capability (cookie blocking, proxy routing, WebRTC protection) is OFF by default and only activates when the user explicitly enables it in the popup. The core PII-masking feature requires only reading from and writing to chat input fields on the supported AI domains.
```

### Remote code
```
No — no remotely hosted code. Manifest V3, all logic bundled locally.
```

---

## 4. Distribution tab

- **Visibility:** Public
- **Publish for all countries** (or restrict regions where VPN routing is regulated, e.g., China/UAE/Russia — recommended to deselect these for the proxy feature).

---

## 5. Submit

1. **Test instructions** (optional): not needed — the extension works on the public ChatGPT/Claude demo; add `https://chatgpt.com` as a test URL if prompted.
2. Click **Submit for review**.
3. Expect **1–7 days**. Because of `webRequestBlocking` + `<all_urls>`, first review may be slower (manual). This is normal — the justification above addresses it.

> **After approval:** you have 30 days to publish. Once listed, Brave and Vivaldi users can install it directly from the Chrome Web Store.

---

## 6. Optional: automate updates via GitHub Actions

After the account exists, you can set up push-to-submit with the official Web Store API:

1. Go to **Chrome Web Store Developer Dashboard → [your item] → API Access** → Create a Google Cloud project, generate **Client ID**, **Client Secret**, and **Refresh Token**.
2. Add repo secrets in GitHub: `CHROME_EXTENSION_ID`, `CHROME_CLIENT_ID`, `CHROME_CLIENT_SECRET`, `CHROME_REFRESH_TOKEN`.
3. A workflow can then run `chrome-webstore-upload-cli` on tag push to update the listing automatically.

(Not wired up yet — say the word and I'll add the workflow once you've created the credentials.)