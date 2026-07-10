# AI Personal Firewall - Browser Extension

A privacy-focused browser extension that automatically detects and masks 30+ types of Personally Identifiable Information (PII) when using AI chat applications. **100% local processing** — no data ever leaves your browser.

## Supported AI Apps (19 Platforms)

| Provider | App | URL |
|----------|-----|-----|
| OpenAI | ChatGPT | chat.openai.com, chatgpt.com |
| Microsoft | Copilot | copilot.microsoft.com |
| Google | Gemini | gemini.google.com, ai.google.dev |
| Anthropic | Claude | claude.ai, claude.anthropic.com |
| Google | AI Chat | chat.google.com |
| Perplexity | Perplexity | perplexity.ai |
| Poe | Poe | poe.com |
| Groq | Groq | groq.com |
| Mistral | Mistral | mistral.ai |
| Cohere | Cohere | cohere.ai |
| Meta | Meta AI | meta.ai |
| DeepSeek | DeepSeek | deepseek.com |
| You.com | You.com | you.com |
| Moonshot | Kimi | kimi.ai |
| Alibaba | Qwen | qwen.ai |
| Jina | Jina AI | jina.ai |
| Phind | Phind | phind.com |

## Features

- **Auto-Detection**: Automatically detects 30+ PII types in your prompts
- **Smart Masking**: Replaces sensitive data with placeholders (e.g., `john@email.com` → `[EMAIL_ADDR_1]`) or realistic fake data
- **Luhn Validation**: Distinguishes real credit card numbers from random digits
- **Confidence Scoring**: Every detection scored 0.0–1.0 with context heuristics
- **Auto-Restore**: AI responses are restored with original values
- **Privacy Dashboard**: View statistics on masked items
- **Toggle Control**: Enable/disable protection anytime

## PII Types Detected (30+)

- Email, phone, SSN, credit card (Luhn-validated), IP address, password, API key
- Crypto wallet (ETH), MAC address, DOB, passport, driver license
- Street address, bank account, routing number
- JWT token, AWS access key, GitHub token, Slack token
- UK National Insurance / NHS, India Aadhaar / PAN, China 18-digit ID
- Canada SIN, Australia TFN, Japan My Number, Brazil CPF/CNPJ, France INSEE

## Installation

### Chrome / Edge / Brave

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `extension` folder from this directory
5. The extension icon will appear in your toolbar

### Firefox

1. Open Firefox and go to `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Navigate to the `firefox` folder and select `manifest.json`
4. The extension icon will appear in your toolbar

## Usage

1. **Click the shield icon** in your browser toolbar to see the dashboard
2. **Toggle protection on/off** using the switch
3. **Navigate to any supported AI app** - protection is automatic
4. **Type normally** - PII is detected and masked automatically
5. **Send your message** - the scrubbed version is sent to the AI
6. **Receive response** - placeholders are restored automatically

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser Extension                        │
├─────────────────────────────────────────────────────────────┤
│  content.js     │  Monitors AI app inputs                   │
│  background.js  │  PII scrubbing engine & state management   │
│  popup.html/js  │  User dashboard UI                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      AI Application                          │
│  chat.openai.com / claude.ai / gemini.google.com / etc.     │
└─────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Intercept**: User types in AI app input field
2. **Detect**: Extension scans text for PII patterns
3. **Scrub**: PII is replaced with unique placeholders
4. **Send**: Scrubbed prompt goes to AI API
5. **Restore**: AI response placeholders are swapped back
6. **Display**: User sees response with original PII values

## Privacy

- **100% Local Processing**: No data is sent to external servers
- **No Logging**: PII values are never stored or transmitted
- **Open Source**: Review the code to verify privacy guarantees

## Files

```
extension/
├── manifest.json      # Extension configuration
├── background.js      # Core PII detection engine
├── content.js         # AI app input monitoring
├── popup.html         # Dashboard UI
├── popup.js           # Dashboard logic
├── styles.css         # Notification styles
└── icons/             # Extension icons
```

## License

MIT License - Use freely, modify as needed.