# Free VPN server — $0 setup

The only component that costs money is the WireGuard server (a VPS). There are
two permanently **free** tiers that run WireGuard fine. Either one removes the
~$4/mo cost entirely — after the (free) account, everything else is $0 forever.

> Why not a "free VPN provider"? Free public VPNs are third-party-operated:
> they see your metadata, cap your bandwidth, and their IPs are often blocked.
> This repo's whole point is *your* server, *your* keys, zero logging. The free
> tiers below give you exactly that for $0.

---

## Option A — Oracle Cloud "Always Free" (recommended)

Oracle's free tier includes a permanent ARM VM (4 OCPUs, 24 GB RAM, 200 GB disk)
that runs WireGuard with room to spare. It never expires and never bills.

1. Create a free account: `https://www.oracle.com/cloud/free/`
   (needs a card for identity verification, **no charge**).
2. Console → **Compute → Instances → Create instance**.
3. Name it anything. Image: **Ubuntu 24.04**. Keep the default **VM.Standard.A1.Flex**
   shape (that's the always-free ARM).
4. Set an **SSH key** (create one on your machine — see below).
5. Create. Copy the instance's **public IP** and the SSH username **`ubuntu`**.

**Generate an SSH key (once, on your machine):**
```bash
ssh-keygen -t ed25519 -C "vpn" -f ~/.ssh/vpn      # keep the passphrase blank or enter one
cat ~/.ssh/vpn.pub                                # paste this into Oracle's SSH key box
```

**Then run the one-command installer:**
```bash
node vpn/setup.mjs --host YOUR_ORACLE_IP --user ubuntu
```

**Open the WireGuard UDP port in Oracle's firewall** (VCN → Security List → Add
Ingress Rule): allow **UDP 51820** from `0.0.0.0/0`. This is the only non-scripted
step — Oracle blocks ports by default.

> Your own machine must have an SSH key installed on the VPS. `setup.mjs` scp's
> the deploy script using that key, so make sure `ssh ubuntu@YOUR_IP` works first.

---

## Option B — Google Cloud free e2-micro

Google's free tier is smaller (1 vCPU / 1 GB RAM) but plenty for a personal VPN.

1. Create an account (card required for identity, no charge): `https://cloud.google.com/free/`
2. Compute Engine → **Create Instance**. Machine type: **e2-micro** (marked *free*),
   region: any `-a`/`-b`/`-c` free region. Boot disk: **Ubuntu 24.04**.
3. Add your SSH public key (same `~/.ssh/vpn.pub` as above), user **`ubuntu`**.
4. **Static IP**: External IP → *Reserve static* (free) so the endpoint never changes.
5. **Firewall**: VPC → Firewall → add rule allowing **UDP 51820**.
6. Then:
```bash
node vpn/setup.mjs --host YOUR_GOOGLE_IP --user ubuntu
```

---

## Notes

- Both tiers are genuinely free and don't expire, but neither is a bulletproof SLA —
  keep a backup of `vpn-out/` configs in case you ever rebuild the instance.
- If you already have a paid VPS, none of this changes — the wizard works identically.
- These cloud accounts verify identity with a card but never bill you for the free tier.
- The kill switch + extension "Connect VPN" flow is unchanged: after `setup.mjs`
  finishes, hit **Connect VPN** in the popup.
