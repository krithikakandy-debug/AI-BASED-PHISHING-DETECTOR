const SUSPICIOUS_KEYWORDS = ["login","signin","sign-in","verify","verification","secure","security","update","account","banking","confirm","wallet","password","credential","paypal","amazon","google","microsoft","apple","netflix","support","recover","unlock","suspended","alert"];
const URL_SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","rebrand.ly"];

function analyzeUrl(rawUrl) {
  let score = 0;
  const riskFactors = [];
  const details = {};
  let parsedUrl;
  try { parsedUrl = new URL(rawUrl); }
  catch { return { score: 100, riskFactors: ["URL could not be parsed"], details: { "URL Format": "Invalid" } }; }

  const protocol = parsedUrl.protocol;
  const hostname = parsedUrl.hostname;
  const fullUrl = rawUrl.toLowerCase();
  const parts = hostname.split(".");

  const isHttps = protocol === "https:";
  details["HTTPS Encryption"] = isHttps ? "Yes — encrypted" : "No — unencrypted";
  if (!isHttps) { score += 20; riskFactors.push("No HTTPS — connection is not encrypted"); }

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  details["IP Address Used"] = isIp ? "Yes — suspicious" : "No — uses domain";
  if (isIp) { score += 30; riskFactors.push("Uses raw IP address instead of domain name"); }

  const subCount = Math.max(0, parts.length - 2);
  details["Subdomain Depth"] = subCount <= 1 ? `${subCount} — normal` : `${subCount} — suspicious`;
  if (subCount > 2) { score += (subCount - 2) * 15; riskFactors.push(`Excessive subdomains (${subCount} levels)`); }

  const matched = SUSPICIOUS_KEYWORDS.filter(kw => fullUrl.includes(kw));
  details["Suspicious Keywords"] = matched.length > 0 ? `Found: ${matched.join(", ")}` : "None detected";
  if (matched.length > 0) { score += Math.min(40, matched.length * 10); riskFactors.push(`Phishing keywords: ${matched.join(", ")}`); }

  const urlLen = rawUrl.length;
  details["URL Length"] = urlLen <= 75 ? `${urlLen} chars — normal` : urlLen <= 100 ? `${urlLen} chars — long` : `${urlLen} chars — very long`;
  if (urlLen > 100) { score += 20; riskFactors.push(`Very long URL (${urlLen} chars)`); }
  else if (urlLen > 75) { score += 10; riskFactors.push(`Long URL (${urlLen} chars)`); }

  const isShortener = URL_SHORTENERS.some(s => hostname.endsWith(s));
  details["URL Shortener"] = isShortener ? "Detected — hides destination" : "Not detected";
  if (isShortener) { score += 15; riskFactors.push("URL shortener — real destination hidden"); }

  const hasAt = rawUrl.includes("@");
  details["@ Symbol in URL"] = hasAt ? "Found — redirect trick" : "Not found — clean";
  if (hasAt) { score += 20; riskFactors.push("@ symbol — browser redirect trick"); }

  const hyphens = (hostname.match(/-/g) || []).length;
  details["Hyphens in Domain"] = hyphens === 0 ? "None — clean" : `${hyphens} — suspicious`;
  if (hyphens > 0) { score += Math.min(15, hyphens * 5); riskFactors.push(`${hyphens} hyphen(s) — possible brand impersonation`); }

  const hasNums = /\d/.test(hostname);
  details["Numbers in Domain"] = hasNums && !isIp ? "Found — possible homograph attack" : "Not found — clean";
  if (hasNums && !isIp) { score += 10; riskFactors.push("Numbers in domain — possible homograph attack"); }

  details["Domain"] = hostname;
  details["Protocol"] = protocol.replace(":", "").toUpperCase();

  return { score: Math.max(0, Math.min(100, score)), riskFactors, details };
}

function scoreToStatus(score) {
  if (score <= 25) return "safe";
  if (score <= 60) return "suspicious";
  return "dangerous";
}

module.exports = { analyzeUrl, scoreToStatus };
