# Privacy Policy — AI Personal Firewall

**Last updated:** June 2026

## Data Collection

The AI Personal Firewall extension **does not collect, transmit, or store** any personally identifiable information (PII) on remote servers. All processing occurs entirely on your local device.

### What the extension accesses

- **Text typed into AI chat inputs** (ChatGPT, Claude, Gemini, Copilot, and other supported platforms). This text is read only to detect and mask PII before it is sent to the AI provider.
- **Page content** on supported AI chat domains, solely to locate input fields and attach PII detection listeners.

### What is stored locally

- **Usage statistics** (number of requests scrubbed, count of PII items detected per type) are saved to `chrome.storage.local`. These stats never leave your browser and can be cleared at any time via the "Clear Statistics" button in the extension popup.

## How Data Is Processed

1. When you type into an AI chat input, the extension scans the text using client-side regular expression patterns and Luhn checksum validation.
2. Detected PII is replaced with placeholder tokens (e.g., `[EMAIL_ADDR_1]`) or realistic fake data (if realistic mode is enabled).
3. The masked text is then sent to the AI provider — your sensitive data never reaches their servers.
4. On AI response, the extension restores original values from a local map that is discarded when the page is refreshed.

## Data Sharing

**No data is shared with any third party.** The extension makes no network requests of its own. It only modifies text within your browser before it is sent to the AI platform you are using.

## Data Retention

- PII maps are held in memory only and cleared on page navigation or refresh.
- Statistics stored in `chrome.storage.local` persist across sessions but are cleared when you click "Clear Statistics."

## Security

Because all detection and masking occurs client-side with no data egress, there is no risk of server-side data breach or unauthorized remote access to your PII.

## Changes to This Policy

If this policy is updated, the version number and "Last updated" date at the top will reflect the change.

## Contact

For questions or concerns, open an issue at:
https://github.com/louiesesther-prog/ai-firewall/issues
