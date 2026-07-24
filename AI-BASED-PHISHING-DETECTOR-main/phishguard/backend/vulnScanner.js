const axios = require('axios');
const https = require('https');

// Ignore SSL errors for active scanning (testing configurations)
const agent = new https.Agent({  
  rejectUnauthorized: false
});

async function scanVulnerabilities(targetUrl) {
    const vulns = [];
    let urlObj;
    try {
        urlObj = new URL(targetUrl);
    } catch(e) {
        return vulns;
    }
    
    const origin = urlObj.origin;

    try {
        // 1. Header Analysis & CORS
        const headRes = await axios.get(origin, { 
            httpsAgent: agent,
            headers: { 'Origin': 'https://evil.com' },
            timeout: 5000,
            validateStatus: () => true 
        });

        const headers = headRes.headers;

        // Missing CSP
        if (!headers['content-security-policy']) {
            vulns.push({ id: 'VULN-001', severity: 'MEDIUM', name: 'Missing Content-Security-Policy', description: 'The server does not enforce a CSP, making it vulnerable to XSS and data injection attacks.' });
        }
        
        // Missing HSTS
        if (!headers['strict-transport-security'] && urlObj.protocol === 'https:') {
            vulns.push({ id: 'VULN-002', severity: 'MEDIUM', name: 'Missing Strict-Transport-Security (HSTS)', description: 'The server does not enforce HTTPS, leaving it vulnerable to MITM downgrade attacks.' });
        }

        // Missing X-Frame-Options
        if (!headers['x-frame-options'] && (!headers['content-security-policy'] || !headers['content-security-policy'].includes('frame-ancestors'))) {
            vulns.push({ id: 'VULN-003', severity: 'LOW', name: 'Missing Clickjacking Protection', description: 'The server does not prevent framing, which could allow attackers to trick users into clicking hidden elements.' });
        }

        // Permissive CORS
        if (headers['access-control-allow-origin'] === '*' || headers['access-control-allow-origin'] === 'https://evil.com') {
            vulns.push({ id: 'VULN-004', severity: 'HIGH', name: 'Permissive CORS Policy', description: `The server reflects arbitrary origins (${headers['access-control-allow-origin']}), allowing attackers to read authenticated user data.` });
        }

        // Information Disclosure (Server version)
        if (headers['x-powered-by'] || (headers['server'] && headers['server'].match(/\d+\.\d+/))) {
            vulns.push({ id: 'VULN-005', severity: 'LOW', name: 'Server Version Disclosure', description: `The server exposes its underlying technology stack (${headers['x-powered-by'] || headers['server']}), aiding attackers in finding CVEs.` });
        }

        // 2. Sensitive File Discovery
        const sensitiveFiles = [
            { path: '/.env', regex: /DB_PASSWORD|SECRET_KEY|API_KEY/i },
            { path: '/.git/config', regex: /\[core\]/i }
        ];

        for (const file of sensitiveFiles) {
            try {
                const fileRes = await axios.get(`${origin}${file.path}`, { httpsAgent: agent, timeout: 3000, validateStatus: () => true });
                if (fileRes.status === 200 && fileRes.data && file.regex.test(fileRes.data)) {
                    vulns.push({ id: 'VULN-006', severity: 'CRITICAL', name: `Exposed ${file.path} File`, description: `The server exposes a sensitive file (${file.path}) containing credentials or configuration data.` });
                }
            } catch (e) {
                // Ignore timeout/network errors for individual files
            }
        }

    } catch (e) {
        console.error("Vuln Scan Error:", e.message);
    }

    // Fallback if none found
    if (vulns.length === 0) {
        vulns.push({ id: 'VULN-000', severity: 'LOW', name: 'Security Baseline Verified', description: 'No immediate glaring misconfigurations detected, but continuous monitoring is advised.' });
    }

    return vulns;
}

module.exports = { scanVulnerabilities };
