# dontencode.ai

**Automated Website Security Audit, Client Source Code Protection, Edge Firewall & AI Search (`/llms.txt`) Optimization for Modern Web Applications.**

---

## Overview

**dontencode.ai** scans any live website URL in seconds to identify exposed client-side JavaScript logic, leaked cloud storage URLs and API tokens, missing HTTP browser security headers, and missing `/llms.txt` manifests for AI search engines (ChatGPT, Perplexity, Claude, and Google AI).

Beyond auditing, **dontencode.ai** provides a 6-layer edge protection engine and 1-command CLI installer that protects web applications without breaking Server-Side Rendering (SSR) or search engine indexing:

1. **Client Code & API Protection (`aegis-compiler.mjs`)** — Compiles sensitive client-side JavaScript functions into polymorphic stack bytecode (`_aVM`) and seals string constants so automated scrapers and DevTools inspection cannot extract business logic or internal API schemas.
2. **Cloud Asset, Storage & Realtime Vault (`aegis-cloud-asset-shield.mjs`)** — Wraps direct AWS S3, CloudFront, Supabase, Firebase, and WebSocket (`wss://`) URLs in single-use expiring edge tokens and enforces Subresource Integrity (SRI) on scripts.
3. **Anti-Scraping, SSR State & Checkout Defense (`aegis-shopify-commerce-shield.mjs`)** — Scrubs sensitive hydration state (`__NEXT_DATA__`, RSC Flight streams, `__NUXT__`, `__remixContext`, Shopify storefront objects) and enforces tenant-bound object sealing and atomic burst locks.
4. **HTTP Security Headers & Edge Virtual Patching (`aegis-edge-gate.mjs` & `aegis-vuln-autofixer.mjs`)** — Automatically injects `Content-Security-Policy`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy`, and `Permissions-Policy` while stripping server version fingerprints and blocking zero-day exploit payloads at the edge.
5. **Living AI Search (`/llms.txt`) Optimization (`aegis-living-geo.mjs`)** — Automatically extracts verified headings, routes, and pricing from live production HTML on every deploy and serves a cryptographically signed `/llms.txt` manifest for AI search crawlers.
6. **Live URL Diagnostic Scanner & Web Portal (`aegis-audit-engine.mjs` & `aegis-edge-server.mjs`)** — Performs real-time HTTP/TLS fetches, script bundle crawls, security header checks, and `/llms.txt` probes on any live URL, rendering an interactive color-coded scorecard.

---

## Quick Start

### 1. Run the Live Web App & URL Scanner

```bash
PORT=4400 npm run serve
```

Then open `http://127.0.0.1:4400` in your browser and enter any website URL to generate a live security and AI search visibility report.

### 2. Protect Any Website or Project in 1 Command

```bash
# Generate an edge proxy worker for any live URL:
node aegis-cli.mjs init --target https://your-website.com

# Or auto-detect and protect a local project directory (Next.js, Nuxt, Vite, Python, Go, PHP):
node aegis-cli.mjs init --dir ./your-project
```

### 3. Run the Verification Suite

```bash
npm test
```

---

## Repository Structure

- `public/index.html` — **dontencode.ai** web application & interactive collapsible URL audit scorecard
- `aegis-edge-server.mjs` — HTTP edge server & REST endpoints (`POST /api/audit`, `POST /api/simulate-shield`, `GET /llms.txt`)
- `aegis-audit-engine.mjs` — Live URL crawler, script bundle inspector & plain-English diagnostic generator
- `aegis-compiler.mjs` — Polymorphic stack bytecode compiler & AST protection engine
- `aegis-cloud-asset-shield.mjs` — Cloud URL ticket proxy, WebSocket frame encryption & SRI enforcer
- `aegis-edge-gate.mjs` — Edge WAF, HTTP security header sanitizer & crawler verifier
- `aegis-living-geo.mjs` — Automated `/llms.txt` & `ai-plugin.json` synchronization engine
- `aegis-shopify-commerce-shield.mjs` — Storefront & SSR hydration state protector
- `aegis-vuln-autofixer.mjs` — Polyglot vulnerability scanner & auto-remediation engine
- `aegis-cli.mjs` — 1-command CLI installer (`npx dontencode.ai init`)
- `test-benchmark.mjs` — End-to-end verification benchmark suite

---

## License

© 2026 **dontencode.ai**. All rights reserved.
