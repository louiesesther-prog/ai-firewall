# AI Personal Firewall - Safari Extension

A privacy-focused Safari extension that automatically detects and masks Personally Identifiable Information (PII) when using AI chat applications.

## Supported AI Apps

- **ChatGPT** (chat.openai.com)
- **Microsoft Copilot** (copilot.microsoft.com)
- **Google Gemini** (gemini.google.com)
- **Claude** (claude.ai)
- **Google AI Chat** (chat.google.com)
- **Perplexity** (perplexity.ai)
- **Poe** (poe.com)
- **Groq** (groq.com)

## Features

- **Auto-Detection**: Automatically detects PII in your prompts
- **Smart Masking**: Replaces sensitive data with placeholders
- **Privacy Dashboard**: View statistics on masked items
- **Toggle Control**: Enable/disable protection anytime
- **100% Local Processing**: No data sent to external servers

## PII Types Detected (30 types)

- **Contact**: Email, Phone Number, Street Address
- **Financial**: Credit Card (Luhn-validated), SSN, Bank Account, Routing Number
- **Identity**: Passport, Driver License, Date of Birth
- **Infrastructure**: IP Address, MAC Address, Crypto Wallet
- **Credentials**: Password, API Key, JWT Token, AWS Key, GitHub Token, Slack Token
- **i18n**: UK NI, UK NHS, India Aadhaar, India PAN, China ID, Canada SIN
- **i18n+**: Australia TFN, Japan My Number, Brazil CPF, Brazil CNPJ, France INSEE

## Installation (Safari)

### Option 1: From Source (Developer Mode)

1. Open **Safari** → **Preferences** → **Advanced**
2. Check **"Show Develop menu in menu bar"**
3. Close Preferences
4. Click **Develop** menu → **Show Extension Builder**
5. Click the **+** button → **Add Extension**
6. Navigate to this `safari` folder and select it
7. Click **Install**

### Option 2: Build as .safariextz (Package)

1. In Extension Builder, click **Package** → **Create Package**
2. Save the `.safariextz` file
3. Double-click to install

## Usage

1. **Enable the extension** in Safari Preferences → Extensions
2. **Navigate to any supported AI app**
3. **Type normally** - PII is detected automatically
4. **Click the shield icon** in Safari toolbar to view stats

## Files

```
safari/
├── manifest.json      # Safari extension config
├── background.js      # PII detection engine
├── content.js         # AI app input monitoring
├── popup.html         # Dashboard UI
├── popup.js           # Dashboard logic
├��─ styles.css         # Notification styles
└── icons/             # Extension icons
```

## Important Safari Notes

- Safari requires explicit permission for each website
- When prompted, allow access to AI chat sites
- Some features may differ slightly from Chrome version
- Use `browser.*` APIs instead of `chrome.*` APIs

## Privacy

- **100% Local Processing**: No external data transmission
- **No Logging**: PII values are never stored
- **Open Source**: Verify code for privacy guarantees

## License

MIT License