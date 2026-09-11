# Microsoft Edge Add-ons — Submission Packet

Complete submission guide for `AI Personal Firewall` v2.1.1 on Edge Add-ons.
Charge: **free registration, free submission**. Review: ~1–3 business days.

> Package to upload: `dist/ai-firewall-edge.zip` (store-ready, PNG icons, validated, v2.1.1).
> Privacy policy URL: `https://ai-firewall.org/privacy.html` (live and verified).
> Logo: `edge/icons/icon300.png` (300×300, recommended).

---

## 1. Register as an Edge developer (free, one-time)

1. Go to https://developer.microsoft.com/registration — sign in with a **Microsoft account (MSA)** — `@outlook.com`, `@live.com`, or `@hotmail.com`. (Work/school accounts are NOT supported.)
2. In Partner Center → **Account settings → Programs → Microsoft Edge** → **Get started**.
3. Choose account type:
   - **Individual** (recommended — fastest, no company verification) — confirm your publisher display name.
   - Company (slower: days–weeks, requires verification via your approver).
4. Accept the **App Developer Agreement** → **Finish**.
5. Wait for the verification confirmation email (fast for Individual).

Dashboard: https://partner.microsoft.com/dashboard

---

## 2. Submit the extension

1. Partner Center → **Microsoft Edge Add-ons program** → **Create a new extension**.
2. **Upload package** → `dist/ai-firewall-edge.zip`.
3. Enter the required info on the pages below, in order.

### A. Properties page

| Field | Value |
|---|---|
| Category | **Privacy & Security** |
| Website | `https://ai-firewall.org` |
| Support contact detail | `https://ai-firewall.org/support.html` |
| Mature content | **No** (leave unchecked) |

### B. Privacy page (copy-paste)

#### Single Purpose
```
Scrubs personally identifiable information from AI chat prompts locally in the browser before they are sent to AI providers, and restores original values in the AI response.
```

#### Permission justification
Paste this into the justification field:

```
1. storage — saves on/off toggle state and rolling usage statistics (requests scrubbed, PII count per type) to the browser's local extension storage. Nothing is transmitted.
2. cookies — used by the optional cookie-blocking feature to strip third-party cookies from supported AI chat domains when the user enables it in the popup. It is off by default.
3. proxy — used only by the optional Privacy Route feature, which is disabled by default. When enabled, it routes traffic to supported AI-chat domains through a proxy endpoint the user supplies entirely themselves. We operate no proxy servers.
4. privacy — used only while Privacy Route is active, to enforce stricter WebRTC IP-handling for leak protection. Inactive by default.
5. scripting — used to attach the PII detection/replace listener to chat input fields on supported AI chat pages.
6. webRequest + webRequestBlocking — used by the optional cookie-blocking feature to strip cookies from AI chat requests/responses when the user opts in. All logic runs locally.
7. <all_urls> host permission — restricted in code to the 17 supported AI chat domains via the manifest content_scripts "matches" list. The extension does not operate on any other site.

Note: every intrusive capability (cookie blocking, proxy routing, WebRTC protection) is OFF by default and only activates when the user explicitly enables it in the popup. The core PII-masking feature requires only reading from and writing to chat input fields on the supported AI domains.
```

#### Are you using remote code?
```
No — Manifest V3, all logic bundled locally, no remotely hosted code.
```

#### Data usage
Collects **no personal data**. Certify:
- No data is collected, accessed, or transmitted from this extension.
- No data sharing with third parties / no selling of user data / no use of data to determine creditworthiness.
- Data (text typed into AI chat inputs) is processed **locally on the user's device only**.

#### Privacy policy URL
```
https://ai-firewall.org/privacy.html
```

### C. Store listings page (per language: English)

| Field | Value |
|---|---|
| **Extension name** | `AI Personal Firewall` (auto from manifest) |
| **Short description** | Auto from manifest `description` field: `Detect and mask 30+ PII types in AI chat apps. 100% local with confidence scoring and Luhn validation.` |
| **Description** (minimum 250 chars) | Paste the block below |
| **Extension logo** | Upload `edge/icons/icon300.png` (300×300) |
| **Small promotional tile** | `store-images/small-promo.png` (440×280) |
| **Large promotional tile** | `store-images/marquee-promo.png` (1400×560) |
| **Screenshots** (up to 6) | All 3 from `store-images/` (1280×800 ↓) |
| **YouTube video URL** | Omit for now |
| **Search terms** | `privacy, PII, AI, ChatGPT, Claude, Gemini, Copilot, security, data protection, masking, GDPR, HIPAA, PCI-DSS, open source` |

#### Description (≥250 chars — paste exactly)

```
AI Personal Firewall automatically detects and masks Personally Identifiable Information (PII) in your AI chat prompts before they reach the provider. All processing is 100% local — nothing you type ever leaves your browser.

It protects 30+ PII types including email, phone, SSN, credit cards (with Luhn checksum validation), IP addresses, crypto wallets, passwords, API keys, MAC addresses, DOB, passport numbers, driver licenses, addresses, and bank details. It also covers 10 international formats: UK National Insurance and NHS, India Aadhaar and PAN, China 18-digit ID, Canada SIN, Australia TFN, Japan My Number, Brazil CPF and CNPJ, and France INSEE.

Every detection includes a confidence score (0.0–1.0) with context-aware heuristics that reduce false positives from version numbers, math, and product codes. You can mask PII as placeholders or realistic fake data, and original values are automatically restored in the AI response.

Works with ChatGPT, Copilot, Gemini, Claude, Perplexity, Poe, Groq, Mistral, Cohere, Meta AI, DeepSeek, You.com, Kimi, Qwen, Jina, Phind, and Google AI Chat — 17 platforms. Includes a privacy dashboard, one-click on/off toggle, and optional cookie blocking and proxy-routing features that are off by default.

MIT licensed and fully open source.
```

### D. Submit for review

1. Click **Submit to Store** (or Save → Submit).
2. Watch the **Helpful feedback page** in the dashboard after review for any certification issues.
3. Expect **1–3 business days**.

---

## 3. Notes

- **Opera compatibility:** The same `ai-firewall-edge.zip` (or the Chrome ZIP) works for Opera users via [addons.opera.com](https://addons.opera.com) — Opera is Chromium and accepts Chrome/Edge-style MV3 packages. See the Opera Phase 5 notes.
- **Updates:** bump the manifest `version`, rebuild with `package-extensions.ps1`, upload the new ZIP. Each update re-enters review.
- Microsoft recommends including a `short_description`-style manifest field; our `description` field already serves this. Listing stability is fine.