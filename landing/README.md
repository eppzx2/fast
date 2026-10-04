# FAST Public Landing Page

A static, read-only project overview for FAST — Fully Automated SIEM & Threat Intelligence Platform.

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

## Files

- `index.html` — page structure and content
- `styles.css` — responsive dark/premium visual system
- `script.js` — lightweight scroll-reveal only

The landing page intentionally has no API calls and no write operations. It is presentation-only.
