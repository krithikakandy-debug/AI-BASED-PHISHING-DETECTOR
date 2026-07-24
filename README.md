# PhishGuard Pro

A Chrome extension (Manifest V3) that analyzes the page you're on in real time and tells you whether it looks like a phishing site — combining a rule-based URL scorer, forensic-grade domain/SSL/DNS signals, live threat intelligence, and an AI-generated explanation. Built for pentesters, blue teams, SOC analysts, and phishing researchers, not just end users.

## How it works

1. The extension detects the active tab's URL and sends it to a local backend — both automatically via an in-page content script (so a warning banner can appear the moment a risky page loads) and on-demand via the side panel.
2. The backend runs 11 rule-based checks on the URL structure (`analyzer.js`, including typosquat/brand-impersonation detection), queries three threat-intel providers and an LLM, and pulls forensic signals: domain registration age (RDAP), live SSL certificate inspection, and DNS SPF/DMARC posture — all keyless, no extra API signup required.
3. The side panel renders a risk score, verdict, signal breakdown, forensic signals, threat-intel results, a SOC-style deep analysis, and a tamper-evident audit trail of every scan performed.

## Features for security teams

- **In-page warning banner** — injected automatically on any dangerous/suspicious page, not just when the side panel is open.
- **Credential Entry Guard** — intercepts form submissions containing a password or payment field on a flagged high-risk site and warns before submission (DLP-style).
- **Typosquat / brand-impersonation detector** — Levenshtein-distance check against major brand domains (e.g. `paypa1.com` → flagged as a PayPal lookalike).
- **Domain age, SSL certificate, and DNS email-auth (SPF/DMARC) checks** — classic pentest/forensic signals, all free/keyless.
- **Tamper-evident forensic audit trail** — every scan is appended to a local SHA-256 hash chain (`extension/hashchain.js`); the side panel can verify chain integrity and export a signed evidence bundle (JSON) for chain-of-custody reporting.

## Stack

- **Extension**: Manifest V3, side panel UI, vanilla JS
- **Backend**: Node.js + Express (`phishguard/backend`), port 3000
- **AI explanations**: [Groq](https://groq.com/) (`llama-3.1-8b-instant`)
- **Threat intelligence**: [AbuseIPDB](https://www.abuseipdb.com/), [VirusTotal](https://www.virustotal.com/), [urlscan.io](https://urlscan.io/)

## Project structure

```
phishguard/
├── backend/
│   ├── server.js         # Express API — orchestrates analyzer + intel + forensics + Groq
│   ├── analyzer.js       # 11 rule-based URL heuristics incl. typosquat detection
│   ├── package.json
│   └── .env.example      # copy to .env and fill in your API keys
└── extension/
    ├── manifest.json     # MV3 manifest — background + content script
    ├── background.js     # tracks active tab, relays URL, logs the audit trail
    ├── content.js         # in-page warning banner + credential entry guard
    ├── content.css
    ├── hashchain.js       # shared hash-chained audit log (background + side panel)
    └── sidepanel/
        ├── sidepanel.html
        ├── sidepanel.css
        └── sidepanel.js
```

## Setup

### Backend

```bash
cd phishguard/backend
npm install
cp .env.example .env   # then fill in your API keys
npm start               # runs on http://localhost:3000
```

Required environment variables (`phishguard/backend/.env`):

| Variable | Purpose |
| --- | --- |
| `GROQ_API_KEY` | AI-generated executive summaries and SOC analysis |
| `ABUSEIPDB_API_KEY` | IP reputation checks |
| `VIRUSTOTAL_API_KEY` | Multi-engine URL scanning |
| `URLSCAN_API_KEY` | URL scan submission |
| `PORT` | Backend port (default `3000`) |

All three intel keys and the Groq key are optional individually — if a key is missing, that check falls back to a safe default instead of failing the whole request.

### Extension

1. Open `chrome://extensions`, enable **Developer mode**.
2. Click **Load unpacked**, select the `phishguard/extension` folder.
3. Pin the extension and click it to open the side panel — it analyzes the current tab automatically and re-analyzes whenever you switch tabs or navigate.
4. The in-page warning banner and Credential Entry Guard run automatically on every `http(s)` page once the extension is loaded — no side panel needs to be open.

The backend must be running on `localhost:3000` for the extension to work.

## API

`POST /analyze` — heuristic score + threat intel + forensic signals (domain age, SSL, DNS) + AI executive summary.

`POST /deep-scan` — same analysis plus a structured SOC breakdown (technical analysis, attack type, risk justification, recommendation).

Both accept `{ "url": "https://..." }` and are used by the content script's automatic page check, the side panel's auto-analysis, "Run Deep Scan", and "Run Vulnerability Scan" actions.

## Tests

- `cd phishguard/backend && node test_analyzer.js` — typosquat detection + scoring pipeline.
- `cd phishguard/extension && node test_hashchain.js` — audit-log tamper detection.
