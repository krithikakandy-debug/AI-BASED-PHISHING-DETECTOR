// Shared by background.js (service worker, via importScripts) and sidepanel.js (via <script>).
// Builds a hash-chained forensic audit log — each entry's hash covers the previous entry's hash,
// so any edit or deletion breaks the chain and pgVerifyChain() detects it.

async function pgSha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function pgEntryPayload(entry) {
  return JSON.stringify({
    timestamp: entry.timestamp,
    url: entry.url,
    score: entry.score,
    status: entry.status,
    riskFactors: entry.riskFactors || []
  });
}

async function pgAppendAuditEntry(auditLog, { url, score, status, riskFactors }) {
  const prevHash = auditLog.length ? auditLog[auditLog.length - 1].hash : "GENESIS";
  const entry = { timestamp: new Date().toISOString(), url, score, status, riskFactors: riskFactors || [] };
  const hash = await pgSha256(prevHash + pgEntryPayload(entry));
  return { ...entry, prevHash, hash };
}

async function pgVerifyChain(auditLog) {
  let prevHash = "GENESIS";
  for (const entry of auditLog) {
    if (entry.prevHash !== prevHash) return false;
    const recomputed = await pgSha256(entry.prevHash + pgEntryPayload(entry));
    if (recomputed !== entry.hash) return false;
    prevHash = entry.hash;
  }
  return true;
}

if (typeof module !== "undefined") module.exports = { pgSha256, pgAppendAuditEntry, pgVerifyChain };
