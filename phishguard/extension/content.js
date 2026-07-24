// Runs on every page. Silently asks the backend (via background.js) for a risk verdict on the
// current URL, then, if it's risky, (1) shows an in-page warning banner and (2) intercepts form
// submissions that carry a password/payment field so the user gets a real-time DLP-style warning
// before handing credentials to a flagged site.

let pgRiskData = null;

pgInit();

async function pgInit() {
  if (!location.href.startsWith("http")) return;
  try {
    const res = await chrome.runtime.sendMessage({ type: "ANALYZE_URL", url: location.href });
    pgRiskData = res && !res.error ? res.data : null;
  } catch {
    pgRiskData = null;
  }
  if (pgRiskData && (pgRiskData.status === "dangerous" || pgRiskData.status === "suspicious")) {
    pgInjectBanner(pgRiskData);
  }
  pgGuardCredentialForms();
}

function pgInjectBanner(data) {
  if (document.getElementById("__phishguard_banner") || !document.documentElement) return;
  const banner = document.createElement("div");
  banner.id = "__phishguard_banner";
  banner.className = data.status === "dangerous" ? "pg-banner pg-danger" : "pg-banner pg-warn";
  const message =
    data.status === "dangerous"
      ? `PhishGuard Pro: this site scored <strong>${data.score}/100</strong> — flagged as a likely PHISHING / MALICIOUS site.`
      : `PhishGuard Pro: this site scored <strong>${data.score}/100</strong> — shows suspicious characteristics.`;
  banner.innerHTML =
    `<div class="pg-banner-inner">` +
    `<span class="pg-banner-icon">⚠</span>` +
    `<span class="pg-banner-text">${message}</span>` +
    `<button type="button" id="__pg_details" class="pg-btn pg-btn-light">Details</button>` +
    `<button type="button" id="__pg_dismiss" class="pg-btn pg-btn-ghost">Dismiss</button>` +
    `</div>`;
  document.documentElement.appendChild(banner);
  document.getElementById("__pg_dismiss").addEventListener("click", () => banner.remove());
  document.getElementById("__pg_details").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "OPEN_SIDE_PANEL" }).catch(() => {});
  });
}

function pgGuardCredentialForms() {
  document.addEventListener(
    "submit",
    (event) => {
      if (!pgRiskData || pgRiskData.status !== "dangerous") return;
      const form = event.target;
      if (!form || !form.querySelectorAll) return;
      const sensitive = form.querySelector('input[type="password"], input[autocomplete*="cc-"], input[name*="card" i]');
      if (!sensitive) return;
      const proceed = confirm(
        `PhishGuard Pro Warning\n\n` +
          `"${location.hostname}" was flagged HIGH RISK (score ${pgRiskData.score}/100) for likely phishing.\n\n` +
          `You are about to submit a password or payment field to this site. Continue anyway?`
      );
      if (!proceed) event.preventDefault();
    },
    true
  );
}
