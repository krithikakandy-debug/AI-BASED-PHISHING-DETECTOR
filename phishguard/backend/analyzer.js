const dns = require('dns').promises;
const axios = require('axios');

/**
 * PhishGuard Pro URL Analyzer v2
 * Parallel intelligence logic with specific scoring thresholds.
 */

const API_TIMEOUT = 1200; // 1.2s timeout for speed

async function analyzeURL(urlStr, apiKeys = {}) {
    let score = 0;
    const riskFactors = [];
    let hostInfo = null;
    let intelligence = {
        abuseScore: 0,
        vtDetections: 0
    };

    const url = new URL(urlStr);
    const hostname = url.hostname;

    // 1. Parallel Intelligence Fetching (VT v2 + AbuseIPDB + DNS)
    const intelResults = await Promise.allSettled([
        fetchDNS(hostname),
        fetchAbuseIPDB(hostname, apiKeys.abuseIpdb),
        fetchVirusTotalV2(urlStr, apiKeys.virusTotal)
    ]);

    const [dnsRes, abuseRes, vtRes] = intelResults;

    // Parse DNS/Host Info
    if (dnsRes.status === 'fulfilled') hostInfo = dnsRes.value;

    // Parse AbuseIPDB
    if (abuseRes.status === 'fulfilled' && abuseRes.value !== null) {
        intelligence.abuseScore = abuseRes.value;
        if (intelligence.abuseScore > 70) {
            score += 40;
            riskFactors.push({ rule: "Critical Abuse Score", points: 40, desc: `AbuseIPDB high confidence: ${intelligence.abuseScore}%` });
        } else if (intelligence.abuseScore > 30) {
            score += 20;
            riskFactors.push({ rule: "Medium Abuse Score", points: 20, desc: `AbuseIPDB suspicious level: ${intelligence.abuseScore}%` });
        }
    }

    // Parse VirusTotal v2
    if (vtRes.status === 'fulfilled' && vtRes.value !== null) {
        intelligence.vtDetections = vtRes.value;
        if (intelligence.vtDetections > 0) {
            score += 40;
            riskFactors.push({ rule: "VirusTotal Flag", points: 40, desc: `Detections: ${intelligence.vtDetections} engines confirmed thread.` });
        }
    }

    // 2. Base Heuristics (Fallback & Incremental)
    if (url.protocol === 'http:') {
        score += 20;
        riskFactors.push({ rule: "Unencrypted Protocol", points: 20, desc: "Site uses insecure HTTP." });
    }

    const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'banking', 'signin', 'confirm'];
    if (suspiciousKeywords.some(kw => urlStr.toLowerCase().includes(kw))) {
        score += 15;
        riskFactors.push({ rule: "Phish-Keywords", points: 15, desc: "URL contains common phishing terms." });
    }

    if (hostname.split('.').length > 3) {
        score += 10;
        riskFactors.push({ rule: "Subdomain Nesting", points: 10, desc: "Detected suspicious subdomain levels." });
    }

    // --- RED TEAM OFFENSIVE AUDIT ---
    try {
        const headRes = await axios.head(url.origin, { timeout: 2000 });
        const headers = headRes.headers;
        if (!headers['content-security-policy']) riskFactors.push({ rule: 'CSP_MISSING', points: 10, desc: 'Target lacks Content Security Policy; surface enables XSS injection.' });
        if (!headers['x-frame-options']) riskFactors.push({ rule: 'CLICKJACK_RISK', points: 15, desc: 'Missing X-Frame-Options; target susceptible to Clickjacking engagement.' });
        if (headers['server']) riskFactors.push({ rule: 'INFRA_LEAK', points: 5, desc: `Infrastructure identifier leaked: ${headers['server']}` });
    } catch (e) { /* Operational silence on HEAD failures */ }

    // Final Status Mapping
    score = Math.min(score, 100);
    let severity = "LOW";
    if (score > 75) severity = "CRITICAL";
    else if (score > 50) severity = "HIGH";
    else if (score > 25) severity = "MEDIUM";

    // Confidence Calculation
    const signals = [dnsRes, abuseRes, vtRes];
    const signalsUsed = signals.filter(s => s.status === 'fulfilled' && s.value !== null).length;
    const confidence = Math.round(Math.min(100, (signalsUsed / signals.length) * 100));

    return {
        score,
        severity,
        confidence,
        signalsUsed,
        totalSignals: signals.length,
        status: severity,
        details: {
            ...intelligence,
            hostInfo,
            riskFactors,
            https: url.protocol === 'https:',
            ip: hostInfo?.ip || 'Pending'
        }
    };
}

// --- Fetchers ---

async function fetchDNS(hostname) {
    try {
        const addresses = await dns.resolve4(hostname);
        const ip = addresses[0];
        const res = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, { timeout: 1000 });
        return { ip, ...res.data };
    } catch (e) { return null; }
}

async function fetchAbuseIPDB(hostname, key) {
    if (!key) return null;
    try {
        const addresses = await dns.resolve4(hostname);
        const ip = addresses[0];
        const res = await axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
            headers: { Key: key, Accept: 'application/json' },
            timeout: API_TIMEOUT
        });
        return res.data.data.abuseConfidenceScore;
    } catch (e) { return null; }
}

async function fetchVirusTotalV2(url, key) {
    if (!key) return null;
    try {
        const res = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report`, {
            params: { apikey: key, resource: url },
            timeout: API_TIMEOUT
        });
        return res.data.positives || 0;
    } catch (e) { return null; }
}

module.exports = { analyzeURL };
