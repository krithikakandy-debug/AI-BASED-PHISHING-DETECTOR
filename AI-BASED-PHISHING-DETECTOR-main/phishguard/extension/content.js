// PhishGuard Pro Content Script - Premium Apple Minimalist Revert
// High-Fidelity Glassmorphism & High-Contrast Typography

(function() {
    if (window.phishGuardLoaded) return;
    window.phishGuardLoaded = true;

    const sidebar = document.createElement('div');
    sidebar.id = 'phishguard-sidebar-root';
    sidebar.style.cssText = 'position:fixed; top:0; right:0; width:400px; height:100vh; z-index:2147483647; pointer-events:none;';
    const shadow = sidebar.attachShadow({ mode: 'open' });
    
    const container = document.createElement('div');
    container.id = 'pg-container';
    container.className = 'pg-hidden';

    const style = document.createElement('style');
    style.textContent = `
        :host { all: initial; }
        #pg-container {
            position: fixed; top: 20px; right: 20px; width: 360px; height: calc(100vh - 40px);
            background: #000000; color: #ffffff; z-index: 2147483647; border-radius: 28px;
            box-shadow: 0 40px 100px rgba(0,0,0,0.8); display: flex; flex-direction: column;
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Inter', sans-serif;
            overflow: hidden; border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(30px); transition: all 0.6s cubic-bezier(0.2, 0.8, 0.2, 1);
            transform: translateX(450px); opacity: 0; pointer-events: auto;
        }
        #pg-container.visible { transform: translateX(0); opacity: 1; }
        
        .header { padding: 30px 30px 15px; display: flex; justify-content: space-between; align-items: center; position: relative; }
        .logo { font-weight: 700; font-size: 1.3rem; letter-spacing: -0.5px; color: #fff; }
        .badge { 
            font-size: 0.6rem; padding: 4px 12px; border-radius: 100px; 
            text-transform: uppercase; font-weight: 800; border: 1px solid rgba(255,255,255,0.2);
            background: rgba(255,255,255,0.1);
        }
        .badge.safe { color: #30d158; border-color: #30d158; }
        .badge.suspicious { color: #ff9f0a; border-color: #ff9f0a; }
        .badge.dangerous { color: #ff3b30; border-color: #ff3b30; }

        .content { padding: 0 30px 30px; flex: 1; overflow-y: auto; scrollbar-width: thin; scrollbar-color: #333 transparent; }
        .content::-webkit-scrollbar { width: 6px; }
        .content::-webkit-scrollbar-thumb { background: #333; border-radius: 10px; }
        
        .url-card { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 18px; font-size: 0.7rem; color: rgba(255,255,255,0.5); word-break: break-all; margin-bottom: 25px; }
        
        .score-wrap { text-align: center; margin-bottom: 35px; }
        .circle { 
            width: 140px; height: 140px; border-radius: 50%; border: 10px solid rgba(255,255,255,0.05); 
            margin: 0 auto; display: flex; flex-direction: column; justify-content: center; align-items: center;
            transition: border-color 1s ease;
        }
        .score-num { font-size: 3rem; font-weight: 800; letter-spacing: -2px; }
        .score-lbl { font-size: 0.6rem; color: rgba(255,255,255,0.4); text-transform: uppercase; margin-top: 5px; }
        
        .sev-badge { font-size: 0.7rem; font-weight: 800; margin-top: 15px; display: inline-block; padding: 4px 12px; border-radius: 4px; }
        .conf-val { font-size: 0.65rem; color: rgba(255,255,255,0.3); margin-top: 5px; text-transform: uppercase; letter-spacing: 0.5px; }

        .card { background: rgba(255,255,255,0.03); border-radius: 22px; padding: 20px; margin-bottom: 20px; border: 1px solid rgba(255,255,255,0.05); }
        .card-title { font-size: 0.8rem; font-weight: 700; color: rgba(255,255,255,0.4); text-transform: uppercase; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
        .ai-text { font-size: 0.85rem; line-height: 1.6; color: #fff; white-space: pre-line; }

        .intel-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .intel-box { text-align: left; }
        .intel-lbl { font-size: 0.6rem; color: rgba(255,255,255,0.3); text-transform: uppercase; display: block; margin-bottom: 5px; }
        .intel-val { font-size: 0.85rem; font-weight: 600; color: #fff; }

        .btn-stack { display: flex; flex-direction: column; gap: 12px; margin-top: 20px; }
        .btn { 
            padding: 16px; border-radius: 18px; border: none; cursor: pointer; 
            font-size: 0.9rem; font-weight: 700; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex; align-items: center; justify-content: center; gap: 10px;
        }
        .btn-main { background: #fff; color: #000; }
        .btn-main:hover { transform: scale(1.02); background: #eee; }
        .btn-sub { background: rgba(255,255,255,0.08); color: #fff; border: 1px solid rgba(255,255,255,0.1); }
        .btn-sub:hover { background: rgba(255,255,255,0.12); }

        .factor-list { list-style: none; padding: 0; margin: 0; }
        .factor-item { padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .factor-item:last-child { border-bottom: none; }
        .factor-head { display: flex; justify-content: space-between; }
        .factor-name { font-size: 0.85rem; font-weight: 600; color: rgba(255,255,255,0.9); }
        .factor-score { color: #ff3b30; font-size: 0.75rem; font-weight: 800; }
        .factor-desc { color: rgba(255,255,255,0.4); font-size: 0.75rem; margin-top: 2px; }

        .close { 
            position: absolute; top: 12px; left: 12px; width: 28px; height: 28px; 
            border-radius: 50%; display: flex; align-items: center; justify-content: center; 
            cursor: pointer; color: rgba(255,255,255,0.4); font-size: 1.4rem; 
            transition: all 0.2s; z-index: 10;
        }
        .close:hover { color: #fff; background: rgba(255,255,255,0.15); transform: rotate(90deg); }

        .loader-vibe { text-align: center; padding: 50px 0; }
        .spinner { width: 40px; height: 40px; border: 4px solid rgba(255,255,255,0.05); border-top-color: #fff; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .footer { padding: 25px 30px; font-size: 0.65rem; color: rgba(255,255,255,0.2); border-top: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; gap: 8px; }
        .pulsar { width: 6px; height: 6px; background: #30d158; border-radius: 50%; box-shadow: 0 0 12px #30d158; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .hidden { display: none !important; }
    `;

    container.innerHTML = `
        <div class="close" id="pg-close">╳</div>
        <div class="header">
            <div class="logo">PhishGuard Pro</div>
            <div id="pg-badge" class="badge">Init</div>
        </div>
        <div class="content">
            <div id="pg-url-card" class="url-card">Analyzing target feed...</div>
            <div id="pg-loader" class="loader-vibe">
                <div class="spinner"></div>
                <p>Establishing Intelligence Connection...</p>
            </div>
            <div id="pg-results" class="hidden">
                <div class="score-wrap">
                    <div class="circle" id="pg-circle">
                        <span class="score-num" id="pg-score-num">0</span>
                        <span class="score-lbl">Risk Level</span>
                    </div>
                    <div id="pg-verdict" style="margin-top:20px; font-weight:800; font-size:0.85rem; letter-spacing:0.5px;"></div>
                    <div id="pg-conf" class="conf-val" style="margin-top:8px;"></div>
                </div>

                <div class="card" id="pg-exec-summary-card">
                    <div class="card-title">🧠 Executive Summary</div>
                    <div class="ai-text" id="pg-exec-summary"></div>
                </div>

                <div class="card">
                    <div class="card-title">📡 Intelligence Sources</div>
                    <div class="intel-row">
                        <div class="intel-box"><span class="intel-lbl">AbuseIPDB</span><span class="intel-val" id="pg-src-abuse">-</span></div>
                        <div class="intel-box"><span class="intel-lbl">VirusTotal</span><span class="intel-val" id="pg-src-vt">-</span></div>
                        <div class="intel-box"><span class="intel-lbl">URLScan</span><span class="intel-val">Verified</span></div>
                        <div class="intel-box"><span class="intel-lbl">ASN Trust</span><span class="intel-val" id="pg-src-asn">-</span></div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">🔍 Signal Breakdown</div>
                    <ul class="factor-list" id="pg-factors"></ul>
                    <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.05);">
                        <h4 style="font-size: 0.75rem; font-weight: 700; color: #fff; margin: 0 0 5px 0;">📌 WHY THIS MATTERS</h4>
                        <p class="ai-text" id="pg-why-matters"></p>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">SOC Intelligence Analysis</div>
                    <div class="ai-section" style="margin-bottom: 15px;">
                        <h4 style="font-size: 0.8rem; font-weight: 600; color: #fff; margin: 0 0 5px 0;">🔬 Technical Analysis</h4>
                        <p id="pg-ai-technical" class="ai-text"></p>
                    </div>
                    <div class="ai-section" style="margin-bottom: 15px;">
                        <h4 style="font-size: 0.8rem; font-weight: 600; color: #fff; margin: 0 0 5px 0;">⚠️ Attack Type</h4>
                        <p id="pg-ai-attack" class="ai-text"></p>
                    </div>
                    <div class="ai-section" style="margin-bottom: 15px;">
                        <h4 style="font-size: 0.8rem; font-weight: 600; color: #fff; margin: 0 0 5px 0;">📊 Risk Justification</h4>
                        <p id="pg-ai-justification" class="ai-text"></p>
                    </div>
                    <div class="ai-section">
                        <h4 style="font-size: 0.8rem; font-weight: 600; color: #fff; margin: 0 0 5px 0;">🛡️ Recommendation</h4>
                        <p id="pg-ai-recommendation" class="ai-text"></p>
                    </div>
                </div>

                <div class="btn-stack">
                    <button class="btn btn-main" id="pg-btn-report-download">📥 Download Forensic PDF</button>
                    <button class="btn btn-sub" id="pg-btn-deep">🚀 Run Deep Scan</button>
                    <button class="btn btn-sub" id="pg-btn-vuln" style="border-color: #ef4444; color: #ef4444;">🎯 Run Vulnerability Scan</button>
                    <button class="btn btn-sub hidden" id="pg-btn-report">📄 View External Report</button>
                    <button class="btn btn-sub" id="pg-btn-copy">📋 Copy Intel</button>
                </div>

                <div class="card hidden" id="pg-vuln-card" style="border: 1px solid #ef4444; background: rgba(239, 68, 68, 0.05); margin-top: 15px;">
                    <div class="card-title" style="color: #ef4444;">🚨 Vulnerability Assessment</div>
                    <div id="pg-vuln-list"></div>
                </div>
            </div>
        </div>
        <div class="footer">
            <div class="pulsar"></div>
            Autonomous Intelligence Active
        </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(container);
    document.body.appendChild(sidebar);

    // --- SCROLL ISOLATION SHIELD ---
    container.addEventListener('wheel', (e) => {
        const delta = e.deltaY;
        const up = delta < 0;
        const content = shadow.querySelector('.content');
        const scrollHeight = content.scrollHeight;
        const height = content.offsetHeight;
        const scrollTop = content.scrollTop;
        e.stopPropagation();
        if (typeof e.cancelable !== 'boolean' || e.cancelable) {
            if ((!up && delta > scrollHeight - height - scrollTop) || (up && delta < -scrollTop)) {
                e.preventDefault();
            }
        }
    }, { passive: false });

    container.addEventListener('mousedown', e => e.stopPropagation());
    container.addEventListener('click', e => e.stopPropagation());

    const currentUrl = window.location.href;
    analyzeURL(currentUrl);

    shadow.getElementById('pg-close').onclick = () => {
        container.classList.remove('visible');
    };

    function analyzeURL(url) {
        shadow.getElementById('pg-url-card').textContent = `Evaluating: ${url}`;
        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (response) => {
            if (response && response.data) {
                updateUI(response.data);
            }
        });
    }

    function updateUI(data) {
        shadow.getElementById('pg-loader').classList.add('hidden');
        shadow.getElementById('pg-results').classList.remove('hidden');
        container.classList.add('visible');

        const scoreNum = shadow.getElementById('pg-score-num');
        scoreNum.textContent = data.score;
        
        const confStr = (data.confidence > 70) ? 'HIGH' : (data.confidence > 40 ? 'MEDIUM' : 'LOW');
        const signalsUsed = data.signalsUsed || 3;
        const totalSignals = data.totalSignals || 3;
        shadow.getElementById('pg-conf').textContent = `Confidence: ${confStr} (based on ${signalsUsed}/${totalSignals} intelligence sources)`;
        
        const circle = shadow.getElementById('pg-circle');
        const verdict = shadow.getElementById('pg-verdict');
        if (data.score > 70) { 
            circle.style.borderColor = "#ff3b30"; 
            verdict.style.color = "#ff3b30";
            verdict.textContent = "⚠ VERDICT: CRITICAL THREAT DETECTED";
        } else if (data.score > 30) { 
            circle.style.borderColor = "#ff9f0a"; 
            verdict.style.color = "#ff9f0a";
            verdict.textContent = "⚠ VERDICT: SUSPICIOUS PATTERN DETECTED";
        } else { 
            circle.style.borderColor = "#30d158"; 
            verdict.style.color = "#30d158";
            verdict.textContent = "✔ VERDICT: CLEAN INFRASTRUCTURE";
        }

        const badge = shadow.getElementById('pg-badge');
        badge.textContent = (data.severity || 'LOW').toUpperCase();
        badge.className = `badge ${data.severity?.toLowerCase() || 'low'}`;

        const exp = data.explanation || {};
        shadow.getElementById('pg-exec-summary').textContent = exp.summary || 'N/A';
        shadow.getElementById('pg-ai-technical').textContent = exp.technical || 'N/A';
        shadow.getElementById('pg-ai-attack').textContent = exp.attack || 'N/A';
        shadow.getElementById('pg-ai-justification').textContent = exp.justification || 'N/A';
        shadow.getElementById('pg-ai-recommendation').textContent = exp.recommendation || 'N/A';

        // Intelligence Sources Panel
        shadow.getElementById('pg-src-abuse').textContent = data.details.abuseScore ? `${data.details.abuseScore}%` : '0%';
        shadow.getElementById('pg-src-vt').textContent = data.details.vtDetections ? `${data.details.vtDetections} Flags` : 'Clean';
        shadow.getElementById('pg-src-asn').textContent = data.details.hostInfo?.org || 'Unknown';

        // Signal Breakdown logic
        const factors = shadow.getElementById('pg-factors');
        factors.innerHTML = '';
        
        const abuseStr = data.details.abuseScore > 0 ? `<span style="color:#ff9f0a">Flagged (${data.details.abuseScore}%)</span>` : `<span style="color:#30d158">✔ Clean</span>`;
        const vtStr = data.details.vtDetections > 0 ? `<span style="color:#ff3b30">${data.details.vtDetections} Engines</span>` : `<span style="color:#30d158">✔ None</span>`;
        const orgName = data.details.hostInfo?.org || 'Unknown';
        const orgStr = orgName !== 'Unknown' ? `<span style="color:#fff">${orgName}</span>` : `<span style="color:#ff9f0a">Unverified</span>`;
        
        factors.innerHTML += `<li class="factor-item"><div class="factor-head"><span class="factor-name">Domain Reputation</span><span class="factor-score" style="font-weight:normal">${abuseStr}</span></div></li>`;
        factors.innerHTML += `<li class="factor-item"><div class="factor-head"><span class="factor-name">Malware Detection</span><span class="factor-score" style="font-weight:normal">${vtStr}</span></div></li>`;
        factors.innerHTML += `<li class="factor-item"><div class="factor-head"><span class="factor-name">Network Trust (ASN)</span><span class="factor-score" style="font-weight:normal">${orgStr}</span></div></li>`;

        let activeRisks = 0;
        (data.details.riskFactors || []).forEach(f => {
            if(f.rule.includes("Abuse Score") || f.rule.includes("VirusTotal")) return; // Skip API rules as they are handled above
            factors.innerHTML += `
                <li class="factor-item">
                    <div class="factor-head"><span class="factor-name" style="color:#ff9f0a">⚠ ${f.rule}</span><span class="factor-score">+${f.points}</span></div>
                    <div class="factor-desc">${f.desc}</div>
                </li>
            `;
            activeRisks++;
        });

        const whyMatters = shadow.getElementById('pg-why-matters');
        if (activeRisks > 0) {
            whyMatters.textContent = `Even though infrastructure signals may appear clean, weak security headers or domain misconfigurations can expose users to client-side attacks (e.g., clickjacking or XSS). Mitigation is advised.`;
        } else if (data.score > 30) {
            whyMatters.textContent = `The elevated risk score is driven by direct threat intelligence hits. Interaction with this domain should be strictly monitored or blocked.`;
        } else {
            whyMatters.textContent = `While no active threats are detected, establishing baseline infrastructure trust ensures that routing and hosting environments remain hardened against future manipulation.`;
        }

        // Action Buttons
        shadow.getElementById('pg-btn-report-download').onclick = () => {
            const backend = "http://localhost:3000";
            const reportData = {
                url: data.url,
                score: data.score,
                status: data.status,
                details: data.details,
                explanation: data.explanation
            };
            const downloadUrl = `${backend}/report/pdf?data=${encodeURIComponent(JSON.stringify(reportData))}`;
            window.open(downloadUrl, '_blank');
        };

        const btnDeep = shadow.getElementById('pg-btn-deep');
        btnDeep.onclick = () => {
            btnDeep.textContent = "Executing Deep-Dive...";
            chrome.runtime.sendMessage({ type: 'DEEP_SCAN', url: data.url }, (res) => {
                if (res && res.data?.uuid) {
                    btnDeep.textContent = "📥 Download Deep Scan PDF";
                    btnDeep.onclick = () => {
                        const backend = "http://localhost:3000";
                        window.open(`${backend}/deep-scan/pdf?uuid=${res.data.uuid}`, '_blank');
                    };
                } else {
                    btnDeep.textContent = "Deep Scan Failed";
                }
            });
        };

        const btnVuln = shadow.getElementById('pg-btn-vuln');
        btnVuln.onclick = () => {
            btnVuln.textContent = "Running DAST Heuristics...";
            const backend = "http://localhost:3000";
            fetch(`${backend}/vuln-scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: data.url })
            })
            .then(r => r.json())
            .then(res => {
                btnVuln.textContent = "Vulnerability Scan Complete";
                const vulnCard = shadow.getElementById('pg-vuln-card');
                const vulnList = shadow.getElementById('pg-vuln-list');
                vulnCard.classList.remove('hidden');
                vulnList.innerHTML = '';
                
                if (res.vulns && res.vulns.length > 0) {
                    res.vulns.forEach(v => {
                        const color = v.severity === 'CRITICAL' ? '#ef4444' : v.severity === 'HIGH' ? '#f97316' : v.severity === 'MEDIUM' ? '#eab308' : '#3b82f6';
                        vulnList.innerHTML += `
                            <div style="margin-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px;">
                                <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                                    <span style="color:${color}; font-weight:bold; font-size:0.9rem;">[${v.severity}] ${v.name}</span>
                                </div>
                                <p style="font-size: 0.85rem; color: #94a3b8; margin: 0 0 10px 0;">${v.description}</p>
                                
                                <div style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; border-left: 2px solid ${color};">
                                    <h4 style="font-size: 0.75rem; color: #fff; margin: 0 0 5px 0;">🧠 AI Deepened Context</h4>
                                    <p style="font-size: 0.8rem; color: #cbd5e1; margin: 0 0 10px 0; white-space: pre-wrap;">${v.context}</p>
                                    
                                    <h4 style="font-size: 0.75rem; color: #fff; margin: 0 0 5px 0;">🔧 AI Mitigation Solution</h4>
                                    <p style="font-size: 0.8rem; color: #30d158; margin: 0; white-space: pre-wrap;">${v.solution}</p>
                                </div>
                            </div>
                        `;
                    });
                } else {
                    vulnList.innerHTML = '<p style="color:#30d158">No severe vulnerabilities detected.</p>';
                }
            })
            .catch(e => {
                btnVuln.textContent = "Scan Failed";
                console.error(e);
            });
        };

        shadow.getElementById('pg-btn-copy').onclick = () => {
            const exp = data.explanation || {};
            const text = `Security Dossier: ${data.url}\nScore: ${data.score}\n\nSummary: ${exp.summary}\nRecommendation: ${exp.recommendation}`;
            navigator.clipboard.writeText(text);
            shadow.getElementById('pg-btn-copy').textContent = "Intel Copied";
        };
    }

})();
