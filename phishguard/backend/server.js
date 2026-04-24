require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { rateLimit } = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { analyzeURL } = require('./analyzer');
const { scanVulnerabilities } = require('./vulnScanner');
const PDFDocument = require('pdfkit');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Caching (5-minute TTL)
const analysisCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; 

// 2. Security Middlewares
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 100, 
	standardHeaders: 'draft-7',
	legacyHeaders: false,
});

app.use(limiter);
app.use(cors());
app.use(express.json());

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || 'MISSING');

async function getAIExplanation(data, url) {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
    const prompt = `
You are a senior cybersecurity analyst generating a structured threat intelligence report.

IMPORTANT:
- Your response MUST be dynamic and based ONLY on the provided data
- DO NOT use generic phrases like "site appears safe"
- DO NOT repeat the same sentences across different inputs

TARGET:
URL: ${url}

SECURITY SIGNALS:
- HTTPS Enabled: ${data.details.https}
- AbuseIPDB Score: ${data.details.abuseScore}
- VirusTotal Detections: ${data.details.vtDetections}
- Hosting/ISP: ${data.details.hostInfo?.isp || 'Unknown'}
- Risk Factors: ${data.details.riskFactors.map(f => f.rule).join(", ") || "None"}

ANALYSIS INSTRUCTIONS:

1. THREAT SUMMARY
2. TECHNICAL ANALYSIS
3. ATTACK POSSIBILITY
4. RISK JUSTIFICATION
5. RECOMMENDATION

OUTPUT FORMAT (STRICT JSON):

{
  "summary": "",
  "technical": "",
  "attack": "",
  "justification": "",
  "recommendation": ""
}
`;

    const result = await model.generateContent(prompt);
    const responseText = await result.response.text();
    
    // Parse response
    let jsonStr = responseText.trim();
    if (jsonStr.startsWith('\`\`\`json')) {
      jsonStr = jsonStr.replace(/^\`\`\`json\n/, '').replace(/\n\`\`\`$/, '');
    } else if (jsonStr.startsWith('\`\`\`')) {
      jsonStr = jsonStr.replace(/^\`\`\`\n/, '').replace(/\n\`\`\`$/, '');
    }
    
    return JSON.parse(jsonStr);
  } catch (error) {
    console.error("Gemini Error or Parse Error:", error);
    return {
      summary: "AI analysis unavailable.",
      technical: "N/A",
      attack: "N/A",
      justification: "N/A",
      recommendation: "Showing rule-based result."
    };
  }
}

// Helper for API Keys
const getApiKeys = () => ({
  abuseIpdb: process.env.ABUSEIPDB_API_KEY,
  virusTotal: process.env.VIRUSTOTAL_API_KEY,
  urlScan: process.env.URLSCAN_API_KEY
});

// Primary Analysis Endpoint
app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  // Domain Cleanup & Cache Check
  let targetUrl = url;
  let cachedAnalysis = null;
  if (analysisCache.has(targetUrl)) {
    const cached = analysisCache.get(targetUrl);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      console.log(`Cache Hit: ${targetUrl}`);
      cachedAnalysis = cached.data;
    }
  }

  try {
    let analysis;
    if (cachedAnalysis) {
      analysis = cachedAnalysis;
    } else {
      console.log(`🔍 Analyzing URL: ${targetUrl}`);
      const keys = getApiKeys();
      analysis = await analyzeURL(targetUrl, keys);
      console.log(`📊 Score: ${analysis.score} | Status: ${analysis.status}`);
      analysisCache.set(targetUrl, { timestamp: Date.now(), data: analysis });
    }

    // AI Explanation Generation (Optimized: only if score > 20)
    let explanation = {};
    if (analysis.score > 20 && process.env.GEMINI_API_KEY) {
      explanation = await getAIExplanation(analysis, targetUrl);
    } else if (analysis.score <= 20) {
      explanation = {
        summary: "This domain is operating on clean infrastructure with no evidence of malicious activity.",
        technical: "Infrastructure verified via ASN/IP lookups. No malware indicators found across aggregate scans.",
        attack: "No attack vectors identified.",
        justification: "Cross-referenced intelligence from VirusTotal, AbuseIPDB, and direct analysis returned safe signatures.",
        recommendation: "Safe for standard operational interaction."
      };
    } else {
      explanation = {
        summary: "AI analysis unavailable.",
        technical: "N/A",
        attack: "N/A",
        justification: "N/A",
        recommendation: "Showing rule-based result."
      };
    }

    const responseData = { ...analysis, url: targetUrl, explanation };
    res.json(responseData);

  } catch (err) {
    console.error("Critical Analysis Error:", err);
    res.status(500).json({ error: "Analysis service encountered a failure." });
  }
});

// NEW: Deep Scan Endpoint (urlscan.io)
app.post('/deep-scan', async (req, res) => {
  const { url } = req.body;
  const apiKey = process.env.URLSCAN_API_KEY;

  if (!apiKey) return res.status(500).json({ error: "urlscan.io key missing" });

  try {
    console.log(`Starting deep scan for: ${url}`);
    const resScan = await axios.post('https://urlscan.io/api/v1/scan/', {
        url: url,
        visibility: "public"
    }, {
        headers: {
            'API-Key': apiKey,
            'Content-Type': 'application/json'
        }
    });

    const uuid = resScan.data.uuid;
    const resultUrl = resScan.data.result;

    console.log(`Scan initiated: ${uuid}. Waiting for completion...`);

    // Poll urlscan.io until the scan is complete
    let attempts = 0;
    let scanFinished = false;
    while (attempts < 20 && !scanFinished) {
      await new Promise(r => setTimeout(r, 2000)); // Wait 2 seconds
      try {
        // The API returns 200 when the result is fully ready
        const check = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`);
        if (check.data && check.data.task) {
          scanFinished = true;
        }
      } catch (e) {
        // 404 means it's still scanning
      }
      attempts++;
    }

    console.log(`Scan finished for ${uuid}`);

    res.json({
        message: "Deep scan completed",
        reportUrl: resultUrl,
        uuid: uuid
    });
  } catch (err) {
    console.error("Deep Scan Error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to initiate urlscan.io analysis" });
  }
});

app.post('/vuln-scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  try {
    console.log(`Starting Vulnerability Scan for: ${url}`);
    
    // 1. Run Active Heuristic Scanner
    const rawVulns = await scanVulnerabilities(url);

    // 2. Pass findings to Gemini for Deepened Context & Solutions
    if (!process.env.GEMINI_API_KEY) {
      return res.json({ vulns: rawVulns.map(v => ({ ...v, solution: "AI Analysis unavailable (Missing Key)." })) });
    }

    const model = genAI.getGenerativeModel({ model: "gemini-flash-latest" });
    const prompt = `
You are a Senior Application Security Engineer. I have run a deterministic vulnerability scanner against a target and found the following vulnerabilities:
${JSON.stringify(rawVulns, null, 2)}

For EACH vulnerability listed above, provide a structured JSON response containing:
1. "id": The exact ID of the vulnerability.
2. "context": A "Deepened Context" explaining the real-world impact and exploitability of this specific misconfiguration.
3. "solution": The exact mitigation or remediation steps to fix it.

RETURN STRICTLY JSON. Do not include markdown formatting or backticks around the JSON. Output an array of objects.
`;

    const result = await model.generateContent(prompt);
    let aiText = result.response.text().trim();
    
    // Clean up potential markdown formatting
    if (aiText.startsWith('\`\`\`json')) {
      aiText = aiText.substring(7, aiText.length - 3);
    } else if (aiText.startsWith('\`\`\`')) {
      aiText = aiText.substring(3, aiText.length - 3);
    }

    let aiSolutions = [];
    try {
      aiSolutions = JSON.parse(aiText);
    } catch (e) {
      console.error("AI JSON Parse Error in Vuln Scan:", e, aiText);
    }

    // Merge AI solutions back into the vulnerability objects
    const enhancedVulns = rawVulns.map(v => {
      const aiObj = aiSolutions.find(a => a.id === v.id) || {};
      return {
        ...v,
        context: aiObj.context || "Standard impact applies.",
        solution: aiObj.solution || "Ensure standard security hardening guidelines are met."
      };
    });

    res.json({ vulns: enhancedVulns });

  } catch (err) {
    console.error("Vuln Scan Error:", err);
    res.status(500).json({ error: "Failed to complete vulnerability scan" });
  }
});

app.get("/deep-scan/pdf", async (req, res) => {
  try {
    const { uuid } = req.query;
    if (!uuid) return res.status(400).send("Missing uuid");

    const result = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`);
    const data = result.data;

    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=PhishGuard_DeepScan_${uuid}.pdf`);
    
    doc.pipe(res);

    // Header
    doc.rect(0, 0, 595, 80).fill('#0f172a');
    doc.fillColor('#38bdf8').fontSize(24).font('Helvetica-Bold').text('PHISHGUARD PRO', 50, 25);
    doc.fillColor('#94a3b8').fontSize(10).font('Helvetica').text('DEEP SCAN FORENSIC DOSSIER', 50, 55);

    doc.y = 100;
    doc.fillColor('#000000');

    // Overview
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#3b82f6').text('SCAN METADATA', 50);
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#0f172a');
    doc.font('Helvetica-Bold').text('Target URL: ', { continued: true }).font('Helvetica').fillColor('#334155').text(data.page?.url || 'N/A');
    doc.font('Helvetica-Bold').fillColor('#0f172a').text('Primary IP: ', { continued: true }).font('Helvetica').fillColor('#334155').text(data.page?.ip || 'N/A');
    doc.font('Helvetica-Bold').fillColor('#0f172a').text('ASN / Network: ', { continued: true }).font('Helvetica').fillColor('#334155').text(data.page?.asnname || 'N/A');
    doc.font('Helvetica-Bold').fillColor('#0f172a').text('Server Location: ', { continued: true }).font('Helvetica').fillColor('#334155').text(data.page?.country || 'N/A');
    
    doc.moveDown(1.5);

    // Page Statistics
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#3b82f6').text('PAGE STATISTICS', 50);
    doc.moveDown(0.5);
    const stats = data.stats || {};
    doc.fontSize(10).fillColor('#0f172a');
    doc.font('Helvetica-Bold').text('Total Requests: ', { continued: true }).font('Helvetica').fillColor('#334155').text((stats.secureRequests || 0) + (stats.unsecureRequests || 0) || 0);
    doc.font('Helvetica-Bold').fillColor('#0f172a').text('IPv6 Requests: ', { continued: true }).font('Helvetica').fillColor('#334155').text((stats.IPv6Percentage || 0) + '%' || '0%');
    doc.font('Helvetica-Bold').fillColor('#0f172a').text('Contacted Domains: ', { continued: true }).font('Helvetica').fillColor('#334155').text(data.lists?.domains?.length || 0);
    doc.font('Helvetica-Bold').fillColor('#0f172a').text('Contacted IPs: ', { continued: true }).font('Helvetica').fillColor('#334155').text(data.lists?.ips?.length || 0);

    doc.moveDown(1.5);

    // Network Footprint
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#ef4444').text('NETWORK FOOTPRINT (TOP 10 DOMAINS)', 50);
    doc.moveDown(0.5);
    const domains = data.lists?.domains || [];
    const topDomains = domains.slice(0, 10);
    
    if (topDomains.length > 0) {
      topDomains.forEach(d => {
        doc.fontSize(10).font('Helvetica').fillColor('#475569').text(`• ${d}`);
      });
    } else {
      doc.fontSize(10).font('Helvetica').fillColor('#475569').text('No external domains contacted.');
    }

    doc.moveDown(1.5);

    // IPs Footprint
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#ef4444').text('CONTACTED IPs (TOP 10)', 50);
    doc.moveDown(0.5);
    const ips = data.lists?.ips || [];
    const topIps = ips.slice(0, 10);
    
    if (topIps.length > 0) {
      topIps.forEach(ip => {
        doc.fontSize(10).font('Helvetica').fillColor('#475569').text(`• ${ip}`);
      });
    } else {
      doc.fontSize(10).font('Helvetica').fillColor('#475569').text('No external IPs contacted.');
    }

    // Footer
    doc.fontSize(8).fillColor('#94a3b8').text(`Generated automatically by PhishGuard Pro Autonomous Intelligence`, 50, 800, { align: 'center' });

    doc.end();
  } catch (error) {
    console.error("Deep Scan PDF Gen Error:", error);
    res.status(500).send("Error generating PDF.");
  }
});

app.get("/report/pdf", (req, res) => {
  try {
    const dataStr = req.query.data;
    if (!dataStr) {
      return res.status(400).send("Missing report data.");
    }
    const data = JSON.parse(decodeURIComponent(dataStr));

    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=PhishGuard_Report_${data.score}.pdf`);
    
    doc.pipe(res);
    
    // Header styling
    doc.rect(0, 0, 595, 80).fill('#0f172a'); // Dark header background
    doc.fillColor('#38bdf8').fontSize(24).font('Helvetica-Bold').text('PHISHGUARD PRO', 50, 25);
    doc.fillColor('#94a3b8').fontSize(10).font('Helvetica').text('FORENSIC INTELLIGENCE DOSSIER', 50, 55);
    
    doc.y = 100;
    doc.fillColor('#000000');
    
    // Status box
    const boxTop = doc.y;
    doc.rect(50, boxTop, 495, 75).fillAndStroke('#f8fafc', '#cbd5e1');
    doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text('TARGET SPECIFICATION', 65, boxTop + 15);
    doc.fontSize(10).font('Helvetica').text(`URL: ${data.url}`, 65, boxTop + 35);
    doc.text(`Severity: ${data.status || 'LOW'} | Risk Score: ${data.score}/100`, 65, boxTop + 50);
    
    doc.y = boxTop + 100;

    // Risk factors
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#ef4444').text('VULNERABILITY RISK FACTORS', 50);
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#000000');
    
    if (data.details?.riskFactors?.length) {
      data.details.riskFactors.forEach(factor => {
        doc.font('Helvetica-Bold').fillColor('#0f172a').text(`• ${factor.rule} (+${factor.points} pts)`);
        doc.font('Helvetica').fillColor('#475569').text(`  ${factor.desc}`);
        doc.moveDown(0.5);
      });
    } else {
      doc.font('Helvetica').fillColor('#475569').text('No immediate risk factors detected.');
      doc.moveDown(1);
    }

    doc.moveDown(1);
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#3b82f6').text('SOC INTELLIGENCE ANALYSIS', 50);
    doc.moveDown(0.5);

    const exp = data.explanation || {};
    const sections = [
      { title: 'Threat Summary', content: exp.summary },
      { title: 'Technical Analysis', content: exp.technical },
      { title: 'Attack Possibility', content: exp.attack },
      { title: 'Risk Justification', content: exp.justification },
      { title: 'Recommendation', content: exp.recommendation }
    ];

    sections.forEach(sec => {
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#0f172a').text(sec.title.toUpperCase());
      doc.moveDown(0.2);
      doc.fontSize(9).font('Helvetica').fillColor('#334155').text(sec.content || 'N/A');
      doc.moveDown(1);
    });

    // Footer
    doc.fontSize(8).fillColor('#94a3b8').text(`Generated automatically by PhishGuard Pro Autonomous Intelligence`, 50, 800, { align: 'center' });

    doc.end();
  } catch (error) {
    console.error("PDF Gen Error:", error);
    res.status(500).send("Error generating PDF.");
  }
});

app.listen(PORT, () => {
  console.log(`🛡️ PhishGuard Pro running on port ${PORT}`);
});
