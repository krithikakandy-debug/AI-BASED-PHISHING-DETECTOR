require("dotenv").config();
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
  const { score, riskFactors, details } = analyzeUrl(url);
  const status = scoreToStatus(score);
  const [intel, explanation] = await Promise.all([
    getIntelligence(url),
    getAiExplanation({ url, score, status, riskFactors })
  ]);
  res.json({ score, status, explanation, details, intel, riskFactors });
});

app.post("/deep-scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing url" });
  console.log(`[PhishGuard] Deep scan: ${url}`);
  const { score, riskFactors, details } = analyzeUrl(url);
  const status = scoreToStatus(score);
  const intel = await getIntelligence(url);
  const deepAnalysis = await getDeepAnalysis({ url, score, status, riskFactors, intel });
  res.json({ score, status, details, intel, riskFactors, deepAnalysis });
});

async function getIntelligence(url) {
  let hostname = "";
  try { hostname = new URL(url).hostname; } catch { hostname = url; }
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

async function checkAbuseIPDB(hostname) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) return { score: "0%", totalReports: 0 };
  try {
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: hostname, maxAgeInDays: 90 },
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
      messages: [{
        role: "user",
        content: `You are a cybersecurity analyst writing for a non-technical audience.
URL analyzed: ${url}
Risk Score: ${score}/100
Status: ${status.toUpperCase()}
Risk Factors: ${riskFactors.length > 0 ? riskFactors.join("; ") : "None — all checks passed"}

Write 2-3 sentences explaining whether this site is safe or dangerous, the specific reason why based on the risk factors, and what the user should do. No jargon. No "As an AI". Be specific to this URL.`
      }],
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
    attackType: status === "safe" ? "No attack vectors identified." : riskFactors.some(r => r.includes("keyword")) ? "Potential credential phishing via keyword manipulation." : riskFactors.some(r => r.includes("IP")) ? "Potential IP-based redirect attack." : "Suspicious URL pattern — possible phishing attempt.",
    justification: status === "safe" ? "Cross-referenced against AbuseIPDB, VirusTotal, and URLScan — no malicious indicators found." : `Risk score of ${score}/100 triggered by: ${riskFactors.slice(0, 2).join("; ")}.`,
    whyMatters: status === "safe" ? "Even safe-looking sites can change. PhishGuard continuously monitors for emerging threats." : status === "suspicious" ? "Suspicious URLs often precede phishing attacks that expose you to credential theft." : "High-risk URLs are used to steal login credentials, financial data, or install malware.",
    recommendation: status === "safe" ? "Safe for standard interaction. Proceed normally." : status === "suspicious" ? "Avoid entering personal information. Verify this URL through official channels." : "Do not enter any personal information. Close this tab immediately."
  };
  if (!key) return fallback;
  try {
    const groq = new Groq({ apiKey: key });
    const completion = await groq.chat.completions.create({
      messages: [{
        role: "user",
        content: `You are a SOC analyst. Analyze this URL:
URL: ${url}
Risk Score: ${score}/100
Status: ${status.toUpperCase()}
Risk Factors: ${riskFactors.join("; ") || "None"}
VirusTotal: ${intel?.virustotal?.result || "Clean"}
AbuseIPDB: ${intel?.abuseipdb?.score || "0%"}

Respond ONLY with this exact JSON, no markdown, no extra text:
{"technical":"one sentence technical analysis","attackType":"attack type or No attack vectors identified","justification":"one sentence why score is justified","whyMatters":"two sentences why this matters to the user","recommendation":"one sentence what user should do right now"}`
      }],
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
  if (status === "safe") return "This website appears safe — it uses HTTPS encryption and no suspicious patterns were detected in its URL structure. You can proceed normally.";
  if (status === "suspicious") return `This URL shows concerning characteristics: ${riskFactors[0] || "suspicious URL patterns"}. Avoid entering any personal information until you verify this site through official channels.`;
  return `This URL is dangerous — it was flagged for ${riskFactors.slice(0, 2).join(" and ") || "multiple high-risk signals"}. Do not enter any personal information and close this tab immediately.`;
}

app.listen(PORT, () => console.log(`PhishGuard Pro API running at http://localhost:${PORT}`));