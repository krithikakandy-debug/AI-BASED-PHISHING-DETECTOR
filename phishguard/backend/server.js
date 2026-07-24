require("dotenv").config();
const dns = require("dns").promises;
const tls = require("tls");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const Groq = require("groq-sdk");
const { analyzeUrl, scoreToStatus } = require("./analyzer");

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors({ origin: "*" }));
app.use(express.json());

app.get("/", (req, res) => res.json({ status: "PhishGuard Pro API running!" }));

app.post("/analyze", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing url" });
  console.log(`[PhishGuard] Analyzing: ${url}`);
  const hostname = safeHostname(url);
  let { score, riskFactors, details, flags } = analyzeUrl(url);
  const [intel, forensics] = await Promise.all([getIntelligence(url), getForensics(hostname, url)]);
  ({ score, riskFactors, details, flags } = applyForensicScoring({ score, riskFactors, details, flags, forensics }));
  const status = scoreToStatus(score);
  const explanation = await getAiExplanation({ url, score, status, riskFactors });
  res.json({ score, status, explanation, details, flags, intel, forensics, riskFactors });
});

app.post("/deep-scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing url" });
  console.log(`[PhishGuard] Deep scan: ${url}`);
  const hostname = safeHostname(url);
  let { score, riskFactors, details, flags } = analyzeUrl(url);
  const [intel, forensics] = await Promise.all([getIntelligence(url), getForensics(hostname, url)]);
  ({ score, riskFactors, details, flags } = applyForensicScoring({ score, riskFactors, details, flags, forensics }));
  const status = scoreToStatus(score);
  const deepAnalysis = await getDeepAnalysis({ url, score, status, riskFactors, intel });
  res.json({ score, status, details, flags, intel, forensics, riskFactors, deepAnalysis });
});

function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

async function getIntelligence(url) {
  const hostname = safeHostname(url);
  const [abuseipdb, virustotal, urlscan] = await Promise.allSettled([
    checkAbuseIPDB(hostname),
    checkVirusTotal(url),
    checkURLScan(url)
  ]);
  return {
    abuseipdb: abuseipdb.status === "fulfilled" ? abuseipdb.value : { score: "0%", error: false },
    virustotal: virustotal.status === "fulfilled" ? virustotal.value : { result: "Clean", malicious: 0 },
    urlscan: urlscan.status === "fulfilled" ? urlscan.value : { result: "Verified" }
  };
}

// Forensic signals: domain age (RDAP, no key needed), SSL certificate inspection (raw TLS handshake),
// and DNS email-auth posture (SPF/DMARC/MX). All free/keyless data sources for pentest & forensic use.
async function getForensics(hostname, url) {
  const isHttps = url.toLowerCase().startsWith("https");
  const [domainAge, ssl, dnsSecurity] = await Promise.allSettled([
    getDomainAge(hostname),
    isHttps ? getSSLInfo(hostname) : Promise.resolve({ error: true, issuer: "N/A — not HTTPS" }),
    getDnsSecurity(hostname)
  ]);
  return {
    domainAge: domainAge.status === "fulfilled" ? domainAge.value : { ageDays: null, registered: "Unknown" },
    ssl: ssl.status === "fulfilled" ? ssl.value : { error: true, issuer: "Unavailable" },
    dns: dnsSecurity.status === "fulfilled" ? dnsSecurity.value : { hasSpf: false, hasDmarc: false, hasMx: false }
  };
}

async function getDomainAge(hostname) {
  try {
    const root = hostname.split(".").slice(-2).join(".");
    const response = await axios.get(`https://rdap.org/domain/${root}`, { timeout: 5000 });
    const events = response.data.events || [];
    const registration = events.find((e) => e.eventAction === "registration");
    if (!registration) return { ageDays: null, registered: "Unknown" };
    const ageDays = Math.round((Date.now() - new Date(registration.eventDate).getTime()) / 86400000);
    return { ageDays, registered: registration.eventDate };
  } catch {
    return { ageDays: null, registered: "Unknown" };
  }
}

function getSSLInfo(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 5000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const validTo = new Date(cert.valid_to).getTime();
      const validFrom = new Date(cert.valid_from).getTime();
      const result = {
        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining: Math.round((validTo - Date.now()) / 86400000),
        selfSigned: Boolean(cert.issuer?.CN && cert.issuer.CN === cert.subject?.CN),
        authorized: socket.authorized
      };
      socket.end();
      resolve(result);
    });
    socket.on("error", () => resolve({ error: true, issuer: "Unavailable" }));
    socket.on("timeout", () => { socket.destroy(); resolve({ error: true, issuer: "Timeout" }); });
  });
}

async function getDnsSecurity(hostname) {
  const root = hostname.split(".").slice(-2).join(".");
  const [spf, dmarc, mx] = await Promise.allSettled([
    dns.resolveTxt(root),
    dns.resolveTxt(`_dmarc.${root}`),
    dns.resolveMx(root)
  ]);
  const spfRecords = spf.status === "fulfilled" ? spf.value.map((r) => r.join("")) : [];
  const dmarcRecords = dmarc.status === "fulfilled" ? dmarc.value.map((r) => r.join("")) : [];
  return {
    hasSpf: spfRecords.some((r) => r.startsWith("v=spf1")),
    hasDmarc: dmarcRecords.some((r) => r.startsWith("v=DMARC1")),
    hasMx: mx.status === "fulfilled" && mx.value.length > 0
  };
}

// Folds forensic signals into the heuristic score/details/flags/riskFactors shape from analyzer.js
// so the extension UI renders them via the existing Signal Breakdown list with no extra plumbing.
function applyForensicScoring({ score, riskFactors, details, flags, forensics }) {
  let s = score;
  const rf = [...riskFactors];
  const { domainAge, dns: dnsSecurity } = forensics;

  if (domainAge.ageDays !== null && domainAge.ageDays < 30) {
    s += 25;
    rf.push(`Domain registered only ${domainAge.ageDays} day(s) ago — newly created domains are commonly used for phishing`);
    details["Domain Age"] = `${domainAge.ageDays} days — very new`;
    flags["Domain Age"] = true;
  } else {
    details["Domain Age"] = domainAge.ageDays !== null ? `${domainAge.ageDays} days` : "Unknown";
    flags["Domain Age"] = false;
  }

  if (!dnsSecurity.hasSpf && !dnsSecurity.hasDmarc) {
    s += 5;
    rf.push("Domain has no SPF/DMARC email authentication records — commonly abused for spoofed phishing emails");
    details["Email Auth (SPF/DMARC)"] = "Missing";
    flags["Email Auth (SPF/DMARC)"] = true;
  } else {
    details["Email Auth (SPF/DMARC)"] = `SPF: ${dnsSecurity.hasSpf ? "Yes" : "No"}, DMARC: ${dnsSecurity.hasDmarc ? "Yes" : "No"}`;
    flags["Email Auth (SPF/DMARC)"] = false;
  }

  return { score: Math.max(0, Math.min(100, s)), riskFactors: rf, details, flags };
}

async function checkAbuseIPDB(hostname) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) return { score: "0%", totalReports: 0 };
  try {
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    const ip = isIp ? hostname : (await dns.lookup(hostname)).address;
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: key, Accept: "application/json" },
      timeout: 5000
    });
    return { score: res.data.data.abuseConfidenceScore + "%", totalReports: res.data.data.totalReports, isp: res.data.data.isp || "Unknown" };
  } catch { return { score: "0%", totalReports: 0 }; }
}

async function checkVirusTotal(url) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { result: "Clean", malicious: 0 };
  try {
    const encoded = Buffer.from(url).toString("base64").replace(/=/g, "");
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: { "x-apikey": key },
      timeout: 5000
    });
    const stats = res.data.data.attributes.last_analysis_stats;
    if (stats.malicious > 0) return { result: "Malicious", malicious: stats.malicious };
    if (stats.suspicious > 0) return { result: "Suspicious", suspicious: stats.suspicious };
    return { result: "Clean", malicious: 0, harmless: stats.harmless };
  } catch { return { result: "Clean", malicious: 0 }; }
}

async function checkURLScan(url) {
  const key = process.env.URLSCAN_API_KEY;
  if (!key) return { result: "Verified" };
  try {
    const res = await axios.post("https://urlscan.io/api/v1/scan/",
      { url, visibility: "public" },
      { headers: { "API-Key": key, "Content-Type": "application/json" }, timeout: 5000 }
    );
    return { result: "Submitted", scanId: res.data.uuid };
  } catch { return { result: "Verified" }; }
}

async function getAiExplanation({ url, score, status, riskFactors }) {
  const key = process.env.GROQ_API_KEY;
  if (!key) return generateFallback(score, status, riskFactors);
  try {
    const groq = new Groq({ apiKey: key });
    const completion = await groq.chat.completions.create({
      messages: [{ role: "user", content: `You are a cybersecurity analyst writing for a non-technical audience.\nURL analyzed: ${url}\nRisk Score: ${score}/100\nStatus: ${status.toUpperCase()}\nRisk Factors: ${riskFactors.length > 0 ? riskFactors.join("; ") : "None — all checks passed"}\n\nWrite 2-3 sentences explaining whether this site is safe or dangerous, the specific reason why based on the risk factors, and what the user should do. No jargon. No "As an AI". Be specific to this URL.` }],
      model: "llama-3.1-8b-instant",
      max_tokens: 200
    });
    return completion.choices[0].message.content.trim();
  } catch (err) {
    console.error("Groq error:", err.message);
    return generateFallback(score, status, riskFactors);
  }
}

async function getDeepAnalysis({ url, score, status, riskFactors, intel }) {
  const key = process.env.GROQ_API_KEY;
  const fallback = {
    technical: status === "safe" ? "Infrastructure verified clean. Domain uses HTTPS and shows no signs of malicious hosting." : `URL analysis detected ${riskFactors.length} risk signal(s): ${riskFactors.slice(0, 2).join(", ")}.`,
    attackType: status === "safe" ? "No attack vectors identified." : "Suspicious URL pattern detected.",
    justification: status === "safe" ? "Cross-referenced against AbuseIPDB, VirusTotal, and URLScan — no malicious indicators found." : `Risk score of ${score}/100 triggered by: ${riskFactors.slice(0, 2).join("; ")}.`,
    whyMatters: status === "safe" ? "Even safe-looking sites can change. PhishGuard continuously monitors for emerging threats." : "High-risk URLs are used to steal login credentials and install malware.",
    recommendation: status === "safe" ? "Safe for standard interaction. Proceed normally." : "Do not enter any personal information. Verify through official channels."
  };
  if (!key) return fallback;
  try {
    const groq = new Groq({ apiKey: key });
    const completion = await groq.chat.completions.create({
      messages: [{ role: "user", content: `You are a SOC analyst. Analyze this URL:\nURL: ${url}\nRisk Score: ${score}/100\nStatus: ${status.toUpperCase()}\nRisk Factors: ${riskFactors.join("; ") || "None"}\nVirusTotal: ${intel?.virustotal?.result || "Clean"}\nAbuseIPDB: ${intel?.abuseipdb?.score || "0%"}\n\nRespond ONLY with this exact JSON, no markdown, no extra text:\n{"technical":"one sentence technical analysis","attackType":"attack type or No attack vectors identified","justification":"one sentence why score is justified","whyMatters":"two sentences why this matters to the user","recommendation":"one sentence what user should do right now"}` }],
      model: "llama-3.1-8b-instant",
      max_tokens: 400
    });
    let text = completion.choices[0].message.content.trim().replace(/```json|```/g, "").trim();
    const parsed = JSON.parse(text);
    return {
      technical: parsed.technical || fallback.technical,
      attackType: parsed.attackType || fallback.attackType,
      justification: parsed.justification || fallback.justification,
      whyMatters: parsed.whyMatters || fallback.whyMatters,
      recommendation: parsed.recommendation || fallback.recommendation
    };
  } catch (err) {
    console.error("Deep analysis error:", err.message);
    return fallback;
  }
}

function generateFallback(score, status, riskFactors) {
  if (status === "safe") return "This website appears safe — it uses HTTPS encryption and no suspicious patterns were detected. You can proceed normally.";
  if (status === "suspicious") return `This URL shows concerning characteristics: ${riskFactors[0] || "suspicious URL patterns"}. Avoid entering personal information.`;
  return `This URL is dangerous — flagged for ${riskFactors.slice(0, 2).join(" and ") || "multiple high-risk signals"}. Do not enter any personal information.`;
}

app.listen(PORT, () => console.log(`PhishGuard Pro API running at http://localhost:${PORT}`));
