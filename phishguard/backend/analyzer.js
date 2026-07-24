const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "verification",
  "secure", "security", "update", "account", "banking",
  "confirm", "wallet", "password", "credential", "paypal",
  "amazon", "google", "microsoft", "apple", "netflix",
  "support", "recover", "unlock", "suspended", "alert"
];
const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];

const BRAND_DOMAINS = [
  "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com", "paypal.com",
  "netflix.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", "bankofamerica.com",
  "wellsfargo.com", "chase.com", "citibank.com", "dropbox.com", "adobe.com", "ebay.com",
  "yahoo.com", "outlook.com", "gmail.com", "icloud.com", "github.com", "binance.com",
  "coinbase.com", "steamcommunity.com", "spotify.com", "whatsapp.com", "irs.gov", "hmrc.gov.uk"
];

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

// ponytail: brand list is a hardcoded top-30, expand via a data file if false-negative reports come in
function detectTyposquatting(hostname) {
  const root = hostname.split(".").slice(-2).join(".");
  if (BRAND_DOMAINS.includes(root)) return null;
  let closest = null;
  let minDist = Infinity;
  for (const brand of BRAND_DOMAINS) {
    const d = levenshtein(root, brand);
    if (d < minDist) { minDist = d; closest = brand; }
  }
  if (closest && minDist > 0 && minDist <= 2) return { brand: closest, distance: minDist };
  return null;
}

function analyzeUrl(rawUrl) {
  let score = 0;
  const riskFactors = [];
  const details = {};
  const flags = {};
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return {
      score: 100,
      riskFactors: ["URL could not be parsed — invalid format"],
      details: { "URL Format": "Invalid — unparseable URL" },
      flags: { "URL Format": true }
    };
  }

  const protocol = parsedUrl.protocol;
  const hostname = parsedUrl.hostname;
  const fullUrl = rawUrl.toLowerCase();
  const parts = hostname.split(".");

  const isHttps = protocol === "https:";
  details["HTTPS Encryption"] = isHttps ? "Yes — encrypted" : "No — unencrypted";
  flags["HTTPS Encryption"] = !isHttps;
  if (!isHttps) { score += 20; riskFactors.push("No HTTPS — connection is not encrypted"); }

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  details["IP Address Used"] = isIp ? "Yes — suspicious" : "No — uses domain";
  flags["IP Address Used"] = isIp;
  if (isIp) { score += 30; riskFactors.push("Uses raw IP address instead of domain name"); }

  const subCount = Math.max(0, parts.length - 2);
  details["Subdomain Depth"] = subCount <= 1 ? `${subCount} — normal` : `${subCount} — suspicious`;
  flags["Subdomain Depth"] = subCount > 2;
  if (subCount > 2) { score += (subCount - 2) * 15; riskFactors.push(`Excessive subdomains (${subCount} levels)`); }

  const matched = SUSPICIOUS_KEYWORDS.filter(kw => fullUrl.includes(kw));
  details["Suspicious Keywords"] = matched.length > 0 ? `Found: ${matched.join(", ")}` : "None detected";
  flags["Suspicious Keywords"] = matched.length > 0;
  if (matched.length > 0) { score += Math.min(40, matched.length * 10); riskFactors.push(`Phishing keywords detected: ${matched.join(", ")}`); }

  const urlLen = rawUrl.length;
  details["URL Length"] = urlLen <= 75 ? `${urlLen} chars — normal` : urlLen <= 100 ? `${urlLen} chars — long` : `${urlLen} chars — very long`;
  flags["URL Length"] = urlLen > 75;
  if (urlLen > 100) { score += 20; riskFactors.push(`Very long URL (${urlLen} chars) — possible obfuscation`); }
  else if (urlLen > 75) { score += 10; riskFactors.push(`Long URL (${urlLen} chars)`); }

  const isShortener = URL_SHORTENERS.some(s => hostname.endsWith(s));
  details["URL Shortener"] = isShortener ? "Detected — hides destination" : "Not detected";
  flags["URL Shortener"] = isShortener;
  if (isShortener) { score += 15; riskFactors.push("URL shortener detected — real destination is hidden"); }

  const hasAt = rawUrl.includes("@");
  details["@ Symbol in URL"] = hasAt ? "Found — redirect trick" : "Not found — clean";
  flags["@ Symbol in URL"] = hasAt;
  if (hasAt) { score += 20; riskFactors.push("@ symbol found — browser redirect trick"); }

  const hyphens = (hostname.match(/-/g) || []).length;
  details["Hyphens in Domain"] = hyphens === 0 ? "None — clean" : `${hyphens} — suspicious`;
  flags["Hyphens in Domain"] = hyphens > 0;
  if (hyphens > 0) { score += Math.min(15, hyphens * 5); riskFactors.push(`${hyphens} hyphen(s) in domain — possible brand impersonation`); }

  const hasNums = /\d/.test(hostname);
  details["Numbers in Domain"] = hasNums && !isIp ? "Found — possible homograph attack" : "Not found — clean";
  flags["Numbers in Domain"] = hasNums && !isIp;
  if (hasNums && !isIp) { score += 10; riskFactors.push("Numbers in domain — possible homograph attack"); }

  const typosquat = isIp ? null : detectTyposquatting(hostname);
  details["Brand Impersonation"] = typosquat ? `Looks like ${typosquat.brand} (edit distance ${typosquat.distance})` : "None detected";
  flags["Brand Impersonation"] = Boolean(typosquat);
  if (typosquat) { score += 35; riskFactors.push(`Domain closely resembles ${typosquat.brand} — likely typosquatting/brand impersonation`); }

  details["Domain"] = hostname;
  details["Protocol"] = protocol.replace(":", "").toUpperCase();
  flags["Domain"] = false;
  flags["Protocol"] = !isHttps;

  return { score: Math.max(0, Math.min(100, score)), riskFactors, details, flags };
}

function scoreToStatus(score) {
  if (score <= 25) return "safe";
  if (score <= 60) return "suspicious";
  return "dangerous";
}

module.exports = { analyzeUrl, scoreToStatus, detectTyposquatting };
