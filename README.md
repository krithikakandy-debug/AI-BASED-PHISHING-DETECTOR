# PhishGuard Pro

A Chrome extension (Manifest V3) that analyzes the page you're on in real time and tells you whether it looks like a phishing site — combining a rule-based URL scorer with live threat intelligence and an AI-generated explanation.

## How it works

1. The extension detects the active tab's URL and sends it to a local backend.
2. The backend runs 10 rule-based checks on the URL structure (`analyzer.js`) and, in parallel, queries three threat-intel providers and an LLM.
3. The side panel renders a risk score, verdict, signal breakdown, threat-intel results, and a SOC-style deep analysis.

## Stack

- **Extension**: Manifest V3, side panel UI, vanilla JS
- **Backend**: Node.js + Express (`phishguard/backend`), port 3000
- **AI explanations**: [Groq](https://groq.com/) (`llama-3.1-8b-instant`)
- **Threat intelligence**: [AbuseIPDB](https://www.abuseipdb.com/), [VirusTotal](https://www.virustotal.com/), [urlscan.io](https://urlscan.io/)

## Project structure

```
phishguard/
├── backend/
│   ├── server.js       # Express API — orchestrates analyzer + intel + Groq
│   ├── analyzer.js      # 10 rule-based URL heuristics, returns score/details/flags
│   ├── package.json
│   └── .env.example     # copy to .env and fill in your API keys
└── extension/
    ├── manifest.json    # MV3 manifest
    ├── background.js    # tracks active tab, relays URL to side panel
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

The backend must be running on `localhost:3000` for the extension to work.

## API

`POST /analyze` — heuristic score + threat intel + AI executive summary.

`POST /deep-scan` — same analysis plus a structured SOC breakdown (technical analysis, attack type, risk justification, recommendation).

Both accept `{ "url": "https://..." }` and are used by the side panel's auto-analysis, "Run Deep Scan", and "Run Vulnerability Scan" actions.
