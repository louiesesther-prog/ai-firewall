# AI Firewall VPN

A **full, real native VPN** built on the industry-standard **WireGuard** protocol — the same audited, kernel-native engine used by Mullvad, Proton, and most commercial VPNs. This is not a simulation: it creates a real encrypted tunnel using a kernel virtual-network adapter and routes your traffic through it.

It complements (and stacks with) the **PII Masking** already built into the AI Personal Firewall.

---

## Why WireGuard (and not a custom protocol)?

Building a VPN from scratch (custom crypto + transport + TUN driver) would be dangerous and irresponsible — it's tens of thousands of lines of subtle, security-critical code. WireGuard is:

- **Battle-tested & audited** (used across the industry)
- **Kernel-native** — minimal userspace, very high performance
- **Modern crypto** — Curve25519 (X25519), ChaCha20-Poly1305, BLAKE2s
- **Simple config** — a tiny `.conf` per peer, no CA/expiry complexity

We generate the keys and configs, install the native client/server, and manage the tunnel — the hard, correct parts come from upstream WireGuard.

---

## What's in this folder

| File | Purpose |
|------|---------|
| `generate.mjs` | Node CLI that generates real X25519 keypairs + `server.conf` + one `.conf` per client |
| `server/setup.sh` | Ubuntu/Debian VPS installer: installs WireGuard, enables NAT/forwarding, loads config |
| `client/install.ps1` | Windows native client: installs WireGuard (wintun), imports a `.conf`, connects |
| `client/kill-switch.ps1` | Blocks all traffic outside the tunnel (leak protection if VPN drops) |
| `socks5-bridge.mjs` | Local SOCKS5 proxy over the tunnel — the hook for the extension's Privacy Route |
| `test-bridge.mjs` | End-to-end SOCKS5 bridge test (handshake, echo, BIND/SOCKS4 rejection) |

## Architecture

```
[ Browser (extension Privacy Route) ]          [ Browser (normal sites) ]
        └──────────── || ────────────┘
              SOCKS5 127.0.0.1:1080  ← socks5-bridge.mjs
                        │
                 (routes via default route)
                        ▼
          ┌────────────────────────────┐
          │  WireGuard Tunnel (wintun) │  ← kernel virtual adapter, encrypted
          └─────────────┬──────────────┘
                        │ UDP :51820 (encrypted)
                        ▼
              [ Your VPS server wg0 ]
                NAT / forwarding enabled
                        │
                        ▼
                    Internet
```

- **Client side:** PII masking still runs locally (masking never leaves your device). VPN adds IP / traffic confidentiality for the connection itself.
- **Kill switch** ensures that if the tunnel drops, there is no traffic at all — no real-IP or DNS leak.

## Quick start

### 1. Generate keys + configs (on any machine with Node)

```bash
node vpn/generate.mjs --endpoint YOUR_VPS_PUBLIC_IP --clients 3
# writes vpn-out/server.conf + client1.conf ... clientN.conf
```

### 2. Set up the server (the one component you rent)

You must own/rent a VPS with a public IP (DigitalOcean, Vultr, Hetzner, Linode — a ~$4/mo droplet is plenty). This is the other side of the tunnel; without it there is no VPN destination.

```bash
# on the VPS (Ubuntu/Debian), as root:
sudo bash vpn/server/setup.sh vpn-out/server.conf
```

The script installs WireGuard, enables IP forwarding + NAT masquerade, and starts the service automatically.

> **We do not operate servers for you.** This design keeps you fully in control — zero third-party logging, your encryption keys, your infrastructure.

### 3. Connect the client

**Windows (native, official WireGuard / wintun):**
```powershell
# Run as Administrator
powershell -ExecutionPolicy Bypass -File vpn/client/install.ps1 -Config client1.conf
```

**Enable the kill switch (so nothing leaks if the VPN drops):**
```powershell
powershell -ExecutionPolicy Bypass -File vpn/client/kill-switch.ps1 -On
# ... and when done:
powershell -ExecutionPolicy Bypass -File vpn/client/kill-switch.ps1 -Off
```

**Other clients** — import `clientN.conf` into the official WireGuard mobile/desktop app, or `sudo wg-quick up clientN.conf` on Linux.

### 4. Point the extension's Privacy Route at the tunnel

Start the SOCKS5 bridge (routes browser traffic through the VPN):

```bash
node vpn/socks5-bridge.mjs            # listen 127.0.0.1:1080, or:
node vpn/socks5-bridge.mjs --port 1081
```

Then in the **AI Personal Firewall** extension popup → **Privacy Route**:
```
host: 127.0.0.1   port: 1080   protocol: SOCKS5
```
Every one of the 19 protected AI-chat sites will then travel through your WireGuard VPN.

## Testing

```bash
node vpn/test-bridge.mjs     # SOCKS5 bridge: handshake, echo round-trip, BIND/SOCKS4 rejection
```

## Security notes

- `vpn-out/` contains **private keys** — never commit it (already in `.gitignore`).
- Pre-shared keys (default) add post-quantum resistance to stored-ciphertext decryption.
- Open the server's UDP port (`51820` by default) only for your clients, e.g. `ufw allow 51820/udp`.
- The kill switch is a Windows Firewall filter; verify manually after enabling.

## Limitations

- Requires **admin/root** to create the virtual adapter (unavoidable for any real VPN).
- The **server must be hosted by you** (a VPS). Out of scope here to operate one for you.
- macOS/Linux clients use the official WireGuard tools (import the same `.conf`); this repo's PowerShell installer targets Windows.