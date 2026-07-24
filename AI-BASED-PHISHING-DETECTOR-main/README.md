# 🛡️ PhishGuard Pro: Advanced Threat Intelligence Platform

[![Node.js](https://img.shields.io/badge/Node.js-v18+-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Chrome Extension](https://img.shields.io/badge/Manifest-V3-4285F4?logo=google-chrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![AI Engine](https://img.shields.io/badge/AI-Gemini%20Flash-8E75B2?logo=google-gemini&logoColor=white)](https://deepmind.google/technologies/gemini/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**PhishGuard Pro** is a high-fidelity cybersecurity intelligence platform designed to detect, analyze, and neutralize phishing threats in real-time. By combining deterministic rule-based heuristics with advanced AI-driven forensics, PhishGuard provides a comprehensive security layer directly within the browser side-panel.

---

## 🌟 Core Capabilities

### 1. Real-Time Neural Analysis
PhishGuard monitors browser navigation events and automatically triggers a multi-stage analysis pipeline. It evaluates over 50+ threat signals in under 1.5 seconds.

### 2. Forensic Intelligence Dossiers
Powered by **Google Gemini Flash**, PhishGuard generates verbose, expert-level technical dossiers for every scanned URL, including:
- **Technical Breakdown**: In-depth analysis of infrastructure and code-level signals.
- **Attack Vector Identification**: Prediction of potential phishing methodologies (e.g., credential harvesting, session hijacking).
- **Justification & Scoring**: Transparent logic behind the security verdict.
- **Remediation Steps**: Actionable advice for security researchers or end-users.

### 3. OSINT & Infrastructure Mapping
PhishGuard aggregates intelligence from multiple elite sources:
- **VirusTotal**: Cross-references 70+ security vendors.
- **AbuseIPDB**: Checks infrastructure reputation and historical abuse reports.
- **IP-API**: Maps geographic origin, ISP metadata, and ASN details.
- **Red Team Audit**: Proactively scans for missing security headers (CSP, X-Frame-Options) and infrastructure leaks.

### 4. Forensic PDF Generation
Generate professional, SOC-ready PDF reports with a single click. Reports include visual severity indicators, full technical breakdowns, and network footprint data.

---

## 🛠️ Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | React-based Chrome Extension (Manifest V3), Vanilla JS, Tailwind CSS |
| **Backend** | Node.js, Express.js |
| **AI/ML** | Google Gemini (Generative AI), OpenAI (Legacy Support) |
| **Security** | Express Rate Limit, CORS Hardening, DNS/IP Heuristics |
| **Forensics** | PDFKit, Axios, urlscan.io Integration |

---

## 🚀 Installation & Deployment

### 1. Backend Intelligence Engine
The backend serves as the centralized API for analysis and PDF generation.

```bash
# Clone the repository
git clone https://github.com/your-repo/phishguard.git
cd phishguard/backend

# Install dependencies
npm install

# Configure environment variables (see Configuration section)
cp .env.example .env

# Start the production server
npm start
```

### 2. Chrome Extension
1. Open **Google Chrome** and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** (top-right corner).
3. Click **Load unpacked** and select the `phishguard/extension` folder.
4. Pin the PhishGuard icon to your toolbar for instant access.

---

## ⚙️ Configuration

Create a `.env` file in the `backend/` directory with the following keys:

| Variable | Description | Source |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | **Required** for AI dossiers | [Google AI Studio](https://aistudio.google.com/) |
| `VIRUSTOTAL_API_KEY` | Optional: Multi-engine scans | [VirusTotal](https://www.virustotal.com/) |
| `ABUSEIPDB_API_KEY` | Optional: Reputation checks | [AbuseIPDB](https://www.abuseipdb.com/) |
| `URLSCAN_API_KEY` | Optional: Deep scan reports | [urlscan.io](https://urlscan.io/) |
| `PORT` | API Port (Default: 3000) | - |

---

## 📂 Project Architecture

```text
phishguard/
├── extension/             # Manifest V3 Extension
│   ├── background.js      # Orchestrates tab tracking & API calls
│   ├── content.js         # Content injection & DOM analysis
│   ├── sidepanel/         # Glassmorphic Sidepanel UI
│   └── icons/             # Platform branding assets
└── backend/               # High-Performance API
    ├── server.js          # Express entry point & AI orchestration
    ├── analyzer.js        # Core heuristic & OSINT engine
    ├── vulnScanner.js     # Active vulnerability probing logic
    └── tests/             # Automated analysis test suites
```

---

## 📊 Security Pipeline Flow
1. **Event Trigger**: User navigates to a new URL.
2. **Heuristic Filter**: Backend checks protocol, keywords, and domain structure.
3. **OSINT Fetch**: Parallel requests to VT, AbuseIPDB, and DNS records.
4. **AI Synthesis**: Gemini Flash synthesizes signals into a human-readable dossier.
5. **UI Delivery**: Verdict and forensic data rendered in the Chrome Sidepanel.

---

## 🔮 Roadmap
- [ ] **Heuristic V3**: Integration of DOM-based logo detection (Computer Vision).
- [ ] **Community Blacklist**: P2P sharing of verified phishing signatures.
- [ ] **Enterprise Dashboard**: Centralized management for organizational security teams.
- [ ] **Auto-Blocker**: Optional automated blocking of high-risk domains.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.

---
**Disclaimer**: *PhishGuard is a research and defense tool. While highly accurate, it should be used as part of a defense-in-depth strategy and not as a sole source of security truth.*
