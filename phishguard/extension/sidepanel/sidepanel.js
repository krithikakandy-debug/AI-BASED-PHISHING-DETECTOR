// sidepanel.js - PhishGuard Pro Logic

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'URL_UPDATED') {
    analyzeURL(message.url);
  }
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0] && tabs[0].url && tabs[0].url.startsWith('http')) {
    analyzeURL(tabs[0].url);
  }
});

async function analyzeURL(url) {
  const urlDisplay = document.getElementById('url-display');
  const loading = document.getElementById('loading');
  const results = document.getElementById('analysis-results');
  const statusBadge = document.getElementById('status-badge');
  
  urlDisplay.textContent = url;
  loading.classList.remove('hidden');
  results.classList.add('hidden');
  statusBadge.textContent = "Analyzing...";
  statusBadge.className = "badge";

  chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (response) => {
    loading.classList.add('hidden');
    if (response && response.data) {
      updateUI(response.data);
    } else {
      urlDisplay.textContent = "Security Feed Offline";
    }
  });
}

function updateUI(data) {
  const results = document.getElementById('analysis-results');
  results.classList.remove('hidden');

  const scoreVal = document.getElementById('score-value');
  const statusBadge = document.getElementById('status-badge');
  const circle = document.getElementById('score-circle');
  
  scoreVal.textContent = data.score;
  const statusStr = data.severity || data.status.toUpperCase();
  statusBadge.textContent = `${statusStr} THREAT`;
  statusBadge.className = `badge ${statusStr.toLowerCase()}`;

  document.getElementById('severity-badge').textContent = `${statusStr} THREAT`;
  document.getElementById('severity-badge').className = `badge ${statusStr.toLowerCase()}`;
  document.getElementById('confidence-label').textContent = `Confidence: ${data.confidence || 0}%`;

  if (data.score > 70) circle.style.borderColor = '#ff3b30';
  else if (data.score > 30) circle.style.borderColor = '#ff9f0a';
  else circle.style.borderColor = '#30d158';

  // OSINT Panel
  document.getElementById('intel-abuse').textContent = `${data.details.abuseScore}%`;
  document.getElementById('intel-as').textContent = data.details.hostInfo?.as?.split(' ')[0] || '-';
  document.getElementById('intel-org').textContent = data.details.hostInfo?.org || '-';
  document.getElementById('intel-isp').textContent = data.details.hostInfo?.isp || '-';

  const exp = data.explanation || {};
  document.getElementById('summary').textContent = exp.summary || 'N/A';
  document.getElementById('technical').textContent = exp.technical || 'N/A';
  document.getElementById('attack').textContent = exp.attack || 'N/A';
  document.getElementById('justification').textContent = exp.justification || 'N/A';
  document.getElementById('recommendation').textContent = exp.recommendation || 'N/A';
  
  const list = document.getElementById('details-list');
  list.innerHTML = '';
  const factors = data.details.riskFactors || [];
  factors.forEach(item => {
    const li = document.createElement('li');
    li.className = 'rule-item';
    li.innerHTML = `
      <div class="rule-header">
        <span class="rule-name">${item.rule}</span>
        <span class="rule-pts">+${item.points}</span>
      </div>
      <div class="rule-desc">${item.desc}</div>
    `;
    list.appendChild(li);
  });

  setupActions(data.url, data);
}

function setupActions(url, data) {
  const btnReport = document.getElementById('btn-report-download');
  const btnDeep = document.getElementById('btn-deep');
  const btnCopy = document.getElementById('btn-copy');
  const btnView = document.getElementById('btn-view');

  btnReport.onclick = () => {
      const backend = "http://localhost:3000";
      const reportData = {
          url: url,
          score: data.score,
          status: data.status,
          details: data.details,
          explanation: data.explanation
      };
      const downloadUrl = `${backend}/report/pdf?data=${encodeURIComponent(JSON.stringify(reportData))}`;
      window.open(downloadUrl, '_blank');
  };

  btnDeep.onclick = () => {
    btnDeep.textContent = "Scanning...";
    chrome.runtime.sendMessage({ type: 'DEEP_SCAN', url }, (res) => {
      if (res && res.data?.reportUrl) {
        btnDeep.textContent = "✅ Scan Done";
        btnView.classList.remove('hidden');
        btnView.onclick = () => window.open(res.data.reportUrl, '_blank');
      }
    });
  };

  btnCopy.onclick = () => {
    const exp = data.explanation || {};
    const text = `Report for ${url}\nScore: ${data.score}\n\nSummary: ${exp.summary}\nRecommendation: ${exp.recommendation}`;
    navigator.clipboard.writeText(text);
    btnCopy.textContent = "✅ Copied";
    setTimeout(() => btnCopy.textContent = "📋 Copy Report", 2000);
  };
}
