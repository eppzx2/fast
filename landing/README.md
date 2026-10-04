# FAST Public Landing Page

A static, read-only public overview for FAST — Fully Automated SIEM & Threat Intelligence Platform.

The landing page now includes an **Interactive Demo**. The demo is a client-side replay of sanitized sample events and never executes commands, contacts a FAST backend, attacks an endpoint, or changes infrastructure.

## Deployment

The site has no backend, build step, database, authentication or runtime dependencies.

### Vercel

Create a new Vercel project from the FAST repository and set:

- **Root Directory:** `landing`
- **Framework Preset:** Other
- **Build Command:** leave empty
- **Output Directory:** `.`

Deploy. The site is fully static.

### Render

Create a **Static Site** from the FAST repository and set:

- **Root Directory:** `landing`
- **Build Command:** leave empty
- **Publish Directory:** `.`

No environment variables are required.

## Interactive Demo

Open `demo/index.html` from the landing page using **Try FAST Demo**.

The demo contains four read-only replays:

1. **SSH Brute Force** — Rule `100200` / MITRE `T1110`
2. **Port Scan** — Rule `100211` / MITRE `T1046`
3. **LOLBIN / Masquerading** — Rule `100221` / MITRE `T1036.003`
4. **IOC Feed Update** — Threat feeds → TALON → SQLite → validated CDB → Wazuh

Each replay shows the event stream, processing pipeline, detection/result card, MITRE context where applicable, and sanitized raw event data.

## Files

- `index.html` — public landing page
- `styles.css` — landing page visual system
- `script.js` — lightweight scroll-reveal only
- `demo/index.html` — interactive demo UI
- `demo/styles.css` — demo visual system and responsive layout
- `demo/script.js` — read-only scenario replay logic and sample event data

The landing page and demo intentionally have no API calls and no write operations. The real FAST stack remains a separate Linux deployment.
