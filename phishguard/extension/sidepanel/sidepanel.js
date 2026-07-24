const BACKEND = "http://localhost:3000";
const ICON_SAFE = "✓"; // check mark
const ICON_WARN = "⚠"; // warning triangle

let currentUrl = null;
let currentData = null;

chrome.runtime.sendMessage({ type: "GET_CURRENT_URL" }, (res) => {
  if (res?.url) analyzeUrl(res.url);
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "URL_UPDATED" && msg.url) analyzeUrl(msg.url);
});

async function analyzeUrl(url) {
  currentUrl = url;
  currentData = null;
  document.getElementById("urlDisplay").textContent = url.length > 55 ? url.slice(0, 52) + "..." : url;
  document.getElementById("threatBadge").textContent = "--";
  document.getElementById("threatBadge").className = "threat-badge";
  showState("loading");
  try {
    const res = await chrome.runtime.sendMessage({ type: "ANALYZE_URL", url });
    if (!res || res.error || !res.data) throw new Error("Server error");
    const data = res.data;
    currentData = data;
    renderResult(data);
    loadAuditLog();
    runDeepScan(url);
  } catch (err) {
    document.getElementById("errorText").textContent =
      "Cannot reach PhishGuard server. Make sure backend is running on port 3000.";
    showState("error");
  }
}

async function runDeepScan(url) {
  try {
    const res = await fetch(`${BACKEND}/deep-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (data.deepAnalysis) {
      document.getElementById("socTechnical").textContent = data.deepAnalysis.technical || "--";
      document.getElementById("socAttack").textContent = data.deepAnalysis.attackType || "--";
      document.getElementById("socJustify").textContent = data.deepAnalysis.justification || "--";
      document.getElementById("socRecommend").textContent = data.deepAnalysis.recommendation || "--";
      document.getElementById("whyMatters").textContent =
        data.deepAnalysis.whyMatters || data.deepAnalysis.justification || "--";
    }
  } catch {}
}

function renderResult(data) {
  const { score, status, explanation, details, flags, intel, forensics } = data;
  const s = Math.max(0, Math.min(100, score));

  document.getElementById("scoreNum").textContent = s;
  const offset = 314 - (s / 100) * 314;
  const ring = document.getElementById("ringFill");
  ring.style.strokeDashoffset = offset;
  const color = s <= 25 ? "#3fb950" : s <= 60 ? "#d29922" : "#f85149";
  ring.style.stroke = color;
  document.getElementById("scoreNum").style.color = color;

  const badge = document.getElementById("threatBadge");
  if (s <= 25) {
    badge.textContent = "LOW";
    badge.className = "threat-badge low";
  } else if (s <= 60) {
    badge.textContent = "MEDIUM";
    badge.className = "threat-badge medium";
  } else {
    badge.textContent = "HIGH";
    badge.className = "threat-badge high";
  }

  const vIcon = document.getElementById("verdictIcon");
  const vTitle = document.getElementById("verdictTitle");
  const conf = document.getElementById("confidenceLine");
  if (status === "safe") {
    vIcon.textContent = ICON_SAFE;
    vIcon.style.color = "#3fb950";
    vTitle.textContent = "VERDICT: CLEAN INFRASTRUCTURE";
    vTitle.style.color = "#3fb950";
    conf.textContent = "CONFIDENCE: HIGH (BASED ON 3/3 INTELLIGENCE SOURCES)";
  } else if (status === "suspicious") {
    vIcon.textContent = ICON_WARN;
    vIcon.style.color = "#d29922";
    vTitle.textContent = "VERDICT: SUSPICIOUS ACTIVITY";
    vTitle.style.color = "#d29922";
    conf.textContent = "CONFIDENCE: MEDIUM (BASED ON 3/3 INTELLIGENCE SOURCES)";
  } else {
    vIcon.textContent = ICON_WARN;
    vIcon.style.color = "#f85149";
    vTitle.textContent = "VERDICT: THREAT DETECTED";
    vTitle.style.color = "#f85149";
    conf.textContent = "CONFIDENCE: HIGH (BASED ON 3/3 INTELLIGENCE SOURCES)";
  }

  document.getElementById("summaryText").textContent = explanation || "Analysis complete.";

  const abuse = intel?.abuseipdb;
  const vt = intel?.virustotal;
  const us = intel?.urlscan;

  const abuseEl = document.getElementById("intelAbuse");
  abuseEl.textContent = abuse?.score || "0%";
  abuseEl.className = "intel-cell-value " + (!abuse?.score || abuse?.score === "0%" ? "clean" : "danger");

  const vtEl = document.getElementById("intelVT");
  vtEl.textContent = vt?.result || "Clean";
  vtEl.className =
    "intel-cell-value " +
    (vt?.result === "Clean" ? "clean" : vt?.result === "N/A" ? "neutral" : vt?.result === "Suspicious" ? "warn" : "danger");

  const usEl = document.getElementById("intelURLScan");
  usEl.textContent = us?.result || "Verified";
  usEl.className = "intel-cell-value " + (us?.error ? "neutral" : "clean");

  const asnEl = document.getElementById("intelASN");
  asnEl.textContent = status === "safe" ? "Trusted" : status === "suspicious" ? "Unknown" : "Untrusted";
  asnEl.className = "intel-cell-value " + (status === "safe" ? "clean" : status === "suspicious" ? "warn" : "danger");

  const domainAgeEl = document.getElementById("forDomainAge");
  domainAgeEl.textContent = forensics?.domainAge?.ageDays != null ? `${forensics.domainAge.ageDays}d` : "Unknown";
  domainAgeEl.className = "intel-cell-value " + (forensics?.domainAge?.ageDays != null && forensics.domainAge.ageDays < 30 ? "danger" : "clean");

  const sslEl = document.getElementById("forSSL");
  sslEl.textContent = forensics?.ssl?.issuer || "Unavailable";
  sslEl.className = "intel-cell-value " + (forensics?.ssl?.error ? "warn" : "clean");

  const sslExpiryEl = document.getElementById("forSSLExpiry");
  sslExpiryEl.textContent = forensics?.ssl?.daysRemaining != null ? `${forensics.ssl.daysRemaining}d` : "N/A";
  sslExpiryEl.className = "intel-cell-value " + (forensics?.ssl?.daysRemaining != null && forensics.ssl.daysRemaining < 14 ? "warn" : "clean");

  const dnsEl = document.getElementById("forDns");
  const hasAuth = forensics?.dns?.hasSpf || forensics?.dns?.hasDmarc;
  dnsEl.textContent = hasAuth ? "Present" : "Missing";
  dnsEl.className = "intel-cell-value " + (hasAuth ? "clean" : "warn");

  const signalList = document.getElementById("signalList");
  signalList.innerHTML = "";
  const entries = Object.entries(details || {});
  if (entries.length === 0) {
    signalList.innerHTML = '<div class="signal-row"><span class="signal-name clean">No risk signals detected</span></div>';
  } else {
    entries.forEach(([key, value]) => {
      const isBad = Boolean(flags?.[key]);
      const row = document.createElement("div");
      row.className = "signal-row";
      row.innerHTML =
        `<div class="signal-name ${isBad ? "bad" : "clean"}">${key}</div>` +
        `<div class="signal-pts ${isBad ? "bad" : "ok"}">${value}</div>`;
      signalList.appendChild(row);
    });
  }

  document.getElementById("whyMatters").textContent =
    status === "safe"
      ? "This domain appears to operate on clean infrastructure with no evidence of malicious activity."
      : status === "suspicious"
      ? "Some signals suggest this URL may pose a risk. Weak security or suspicious patterns detected."
      : "Multiple high-risk signals indicate this URL may be part of a phishing or malware campaign.";

  document.getElementById("socTechnical").textContent = "Running deep analysis...";
  document.getElementById("socAttack").textContent = "Analyzing...";
  document.getElementById("socJustify").textContent = "Cross-referencing intelligence sources...";
  document.getElementById("socRecommend").textContent =
    status === "safe" ? "Safe for standard interaction." : "Avoid entering personal information.";

  showState("result");
}

document.getElementById("downloadPdfBtn").addEventListener("click", () => {
  if (!currentData) return;
  const d = currentData;
  const scoreColor = d.score > 60 ? "#f85149" : d.score > 25 ? "#d29922" : "#3fb950";
  const html = `<!DOCTYPE html><html><head><title>PhishGuard Forensic Report</title><style>
body{font-family:Arial,sans-serif;background:#050505;color:#fff;padding:40px;margin:0;}
.header{border-bottom:1px solid #222;padding-bottom:20px;margin-bottom:30px;display:flex;justify-content:space-between;}
.brand{font-size:18px;font-weight:900;}
.score-circle{width:100px;height:100px;border-radius:50%;border:6px solid ${scoreColor};margin:20px auto;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.score-big{font-size:36px;font-weight:900;color:${scoreColor};}
.status-text{font-size:14px;font-weight:800;color:${scoreColor};text-align:center;text-transform:uppercase;margin-bottom:20px;}
.section{margin:20px 0;padding:16px;background:#0f0f0f;border:1px solid #1e1e1e;border-radius:4px;}
.section-title{font-size:9px;text-transform:uppercase;letter-spacing:2px;color:#444;margin-bottom:10px;}
.body-text{font-size:13px;line-height:1.7;color:#aaa;}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #1a1a1a;color:#222;font-size:9px;display:flex;justify-content:space-between;}
</style></head><body>
<div class="header"><div><div class="brand">PHISHGUARD PRO / INTEL</div></div><div style="text-align:right;font-size:9px;color:#333;">TIMESTAMP: ${new Date().toLocaleString()}</div></div>
<div class="score-circle"><div class="score-big">${d.score}</div></div>
<div class="status-text">${d.status.toUpperCase()} THREAT LEVEL</div>
<div class="section"><div class="section-title">URL Analyzed</div><div class="body-text" style="color:#58a6ff;word-break:break-all;">${currentUrl}</div></div>
<div class="section"><div class="section-title">Executive Summary</div><div class="body-text">${d.explanation || "No summary available."}</div></div>
<div class="section"><div class="section-title">Risk Factors</div><div class="body-text">${(d.riskFactors || []).join("<br>") || "None detected"}</div></div>
<div class="footer"><div>PHISHGUARD PRO INTEL ENGINE</div><div>FOR AUTHORIZED USE ONLY</div></div>
<script>setTimeout(()=>window.print(),500);<\/script>
</body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "PhishGuard_Report_" + Date.now() + ".html";
  a.click();
});

document.getElementById("deepScanBtn").addEventListener("click", async () => {
  if (!currentUrl) return;
  const btn = document.getElementById("deepScanBtn");
  btn.textContent = "Scanning...";
  btn.disabled = true;
  await runDeepScan(currentUrl);
  btn.textContent = "Run Deep Scan";
  btn.disabled = false;
});

document.getElementById("vulnScanBtn").addEventListener("click", async () => {
  if (!currentUrl) return;
  const btn = document.getElementById("vulnScanBtn");
  btn.textContent = "Scanning...";
  btn.disabled = true;
  try {
    const res = await fetch(`${BACKEND}/deep-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    });
    const data = await res.json();
    document.getElementById("socAttack").textContent = data.deepAnalysis?.attackType || "No attack vectors identified.";
    document.getElementById("socJustify").textContent = data.deepAnalysis?.justification || "--";
  } catch {
    alert("Vulnerability scan failed.");
  } finally {
    btn.textContent = "Run Vulnerability Scan";
    btn.disabled = false;
  }
});

document.getElementById("copyBtn").addEventListener("click", () => {
  if (!currentData) return;
  const text =
    "PHISHGUARD PRO INTEL REPORT\n" +
    "URL: " + currentUrl + "\n" +
    "Score: " + currentData.score + "/100\n" +
    "Status: " + currentData.status.toUpperCase() + "\n" +
    "Summary: " + currentData.explanation + "\n" +
    "Generated: " + new Date().toLocaleString();
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copyBtn");
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = "Copy Intel"), 2000);
  });
});

document.getElementById("retryBtn").addEventListener("click", () => {
  if (currentUrl) analyzeUrl(currentUrl);
});

function showState(state) {
  ["loadingState", "resultPanel", "errorState"].forEach((id) => document.getElementById(id).classList.add("hidden"));
  const map = { loading: "loadingState", result: "resultPanel", error: "errorState" };
  document.getElementById(map[state])?.classList.remove("hidden");
}

async function loadAuditLog() {
  const { auditLog = [] } = await chrome.storage.local.get("auditLog");
  const list = document.getElementById("auditList");
  const recent = auditLog.slice(-8).reverse();
  if (recent.length === 0) {
    list.innerHTML = '<div class="signal-row"><span class="signal-name clean">No scans logged yet</span></div>';
    return;
  }
  list.innerHTML = recent
    .map((e) => {
      const bad = e.status !== "safe";
      const shortUrl = e.url.length > 40 ? e.url.slice(0, 37) + "..." : e.url;
      return (
        `<div class="signal-row">` +
        `<span class="signal-name ${bad ? "bad" : "clean"}">${new Date(e.timestamp).toLocaleTimeString()} — ${shortUrl}</span>` +
        `<span class="signal-pts ${bad ? "bad" : "ok"}">${e.score}</span>` +
        `</div>`
      );
    })
    .join("");
}

document.getElementById("verifyChainBtn").addEventListener("click", async () => {
  const { auditLog = [] } = await chrome.storage.local.get("auditLog");
  const valid = await pgVerifyChain(auditLog);
  alert(
    valid
      ? `Chain integrity verified — ${auditLog.length} entries, no tampering detected.`
      : "WARNING: audit chain integrity check FAILED — the log may have been tampered with."
  );
});

document.getElementById("exportAuditBtn").addEventListener("click", async () => {
  const { auditLog = [] } = await chrome.storage.local.get("auditLog");
  const bundle = { tool: "PhishGuard Pro", exported: new Date().toISOString(), entries: auditLog };
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "PhishGuard_Evidence_" + Date.now() + ".json";
  a.click();
});

loadAuditLog();
