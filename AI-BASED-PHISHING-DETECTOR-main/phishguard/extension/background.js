const BACKEND_URL = "http://localhost:3000";

// Listen for tab updates to trigger analysis in the side panel (Native Fallback)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url && tab.url.startsWith('http')) {
    chrome.runtime.sendMessage({
      type: 'URL_UPDATED',
      url: tab.url
    }).catch(() => {});
  }
});

// Handle Requests from Content Scripts / Sidepanel
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_URL') {
    fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: message.url })
    })
    .then(res => res.json())
    .then(data => sendResponse({ data }))
    .catch(err => {
      console.error('Relay error:', err);
      sendResponse({ error: true });
    });
    return true; 
  }

  if (message.type === 'DEEP_SCAN') {
    fetch(`${BACKEND_URL}/deep-scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: message.url })
    })
    .then(res => res.json())
    .then(data => sendResponse({ data }))
    .catch(err => {
      console.error('Deep scan error:', err);
      sendResponse({ error: true });
    });
    return true;
  }

  if (message.type === 'GENERATE_REPORT') {
    const reportData = message.data;
    const blobHtml = generateReportHtml(reportData);
    const blob = new Blob([blobHtml], { type: 'text/html' });
    const reader = new FileReader();
    
    reader.onload = function() {
      chrome.downloads.download({
        url: reader.result,
        filename: `PhishGuard_Forensic_Report_${Date.now()}.html`,
        saveAs: true
      });
    };
    reader.readAsDataURL(blob);
    return true;
  }
});

function generateReportHtml(r) {
  const scoreColor = r.score > 70 ? '#ff3b30' : (r.score > 30 ? '#ff9f0a' : '#30d158');
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishGuard Pro - Internal Intelligence Dossier</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&family=Inter:wght@400;700&display=swap');
            body { font-family: 'Inter', sans-serif; background: #050505; color: #fff; padding: 60px; margin: 0; }
            .dossier { max-width: 900px; margin: 0 auto; border: 1px solid rgba(255,255,255,0.1); background: #0a0a0a; padding: 50px; position: relative; overflow: hidden; }
            .watermark { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-45deg); font-size: 8rem; color: rgba(255,255,255,0.02); pointer-events: none; white-space: nowrap; font-weight: 900; }
            
            .header { border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 30px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: flex-start; }
            .brand { font-family: 'Space Grotesk', sans-serif; font-size: 1.5rem; font-weight: 700; letter-spacing: -1px; color: #fff; }
            .classification { color: #ff3b30; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; letter-spacing: 2px; }
            
            .status-block { margin-bottom: 50px; text-align: center; }
            .score-circle { width: 140px; height: 140px; border-radius: 50%; border: 8px solid ${scoreColor}; margin: 0 auto 20px; display: flex; flex-direction: column; justify-content: center; align-items: center; box-shadow: 0 0 30px ${scoreColor}33; }
            .score-num { font-size: 3.5rem; font-weight: 800; line-height: 1; }
            .status-label { font-size: 1.2rem; font-weight: 700; text-transform: uppercase; color: ${scoreColor}; margin-top: 10px; }
            
            .section { margin-bottom: 60px; }
            .section-title { font-family: 'Space Grotesk', sans-serif; font-size: 0.8rem; text-transform: uppercase; color: rgba(255,255,255,0.3); border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 10px; margin-bottom: 25px; display: flex; align-items: center; gap: 10px; }
            
            .intel-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
            .intel-box { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); padding: 20px; border-radius: 4px; }
            .label { font-size: 0.65rem; color: rgba(255,255,255,0.4); text-transform: uppercase; display: block; margin-bottom: 5px; }
            .value { font-size: 1rem; font-weight: 600; }

            .ai-note { padding: 30px; background: ${scoreColor}08; border-left: 4px solid ${scoreColor}; border-radius: 4px; line-height: 1.8; font-size: 1.05rem; }
            
            .v-table { width: 100%; border-collapse: collapse; }
            .v-row { border-bottom: 1px solid rgba(255,255,255,0.05); }
            .v-row td { padding: 15px 0; }
            .v-name { font-weight: 700; font-size: 0.9rem; }
            .v-points { color: #ff3b30; font-weight: 800; font-size: 0.8rem; text-align: right; }
            .v-desc { color: rgba(255,255,255,0.4); font-size: 0.8rem; }

            .footer { margin-top: 100px; padding-top: 30px; border-top: 1px solid rgba(255,255,255,0.05); color: rgba(255,255,255,0.2); font-size: 0.7rem; display: flex; justify-content: space-between; }
            
            @media print { body { background: #fff; color: #000; padding: 0; } .dossier { border: none; padding: 0; } .watermark { color: rgba(0,0,0,0.03); } }
        </style>
    </head>
    <body>
        <div class="dossier">
            <div class="watermark">INTERNAL ONLY</div>
            <div class="header">
                <div>
                    <div class="brand">PHISHGUARD PRO / INTEL</div>
                    <div class="classification">CONIDENTIAL INTELLIGENCE DOSSIER // TOP SECRET</div>
                </div>
                <div style="text-align: right">
                    <div style="font-size: 0.7rem; opacity: 0.5;">CASE ID: ${Math.random().toString(36).substr(2, 9).toUpperCase()}</div>
                    <div style="font-size: 0.7rem; opacity: 0.5;">TIMESTAMP: ${new Date().toLocaleString()}</div>
                </div>
            </div>

            <div class="status-block">
                <div class="score-circle">
                    <div class="score-num">${r.score}</div>
                </div>
                <div class="status-label">${r.status} THREAT LEVEL</div>
            </div>

            <div class="section">
                <div class="section-title">01 / ANALYST STRATEGIC SYNTHESIS</div>
                <div class="ai-note">${r.explanation}</div>
            </div>

            <div class="section">
                <div class="section-title">02 / INFRASTRUCTURE OSINT (OPEN SOURCE INTELLIGENCE)</div>
                <div class="intel-grid">
                    <div class="intel-box"><span class="label">Primary IP</span><span class="value">${r.details.ip}</span></div>
                    <div class="intel-box"><span class="label">ASN / Network</span><span class="value">${r.details.hostInfo?.as || 'N/A'}</span></div>
                    <div class="intel-box"><span class="label">Organization</span><span class="value">${r.details.hostInfo?.org || 'N/A'}</span></div>
                    <div class="intel-box"><span class="label">Geolocation</span><span class="value">${r.details.hostInfo?.city}, ${r.details.hostInfo?.country || 'GLOBAL'}</span></div>
                </div>
            </div>

            <div class="section">
                <div class="section-title">03 / IDENTIFIED ATTACK VECTORS & VULNERABILITIES</div>
                <table class="v-table">
                    ${r.details.riskFactors.map(f => `
                        <tr class="v-row">
                            <td>
                                <div class="v-name">${f.rule}</div>
                                <div class="v-desc">${f.desc}</div>
                            </td>
                            <td class="v-points">+${f.points} PTS</td>
                        </tr>
                    `).join('')}
                </table>
            </div>

            <div class="footer">
                <div>PHISHGUARD PRO INTEL ENGINE V2.1</div>
                <div>CLASSIFIED REPORT - FOR AUTHORIZED PERSONNEL ONLY</div>
            </div>
        </div>
        <script>setTimeout(() => window.print(), 1000);</script>
    </body>
    </html>
  `;
}

// Open side panel on action click (toolbar icon)
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch((error) => console.error(error));


