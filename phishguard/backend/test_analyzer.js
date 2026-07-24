const assert = require("assert");
const { analyzeUrl, scoreToStatus, detectTyposquatting } = require("./analyzer");

// typosquatting: legit brand domain is not flagged
assert.strictEqual(detectTyposquatting("paypal.com"), null);

// typosquatting: one-character-off lookalike is flagged
const hit = detectTyposquatting("paypa1.com");
assert.ok(hit && hit.brand === "paypal.com", "paypa1.com should be flagged as paypal.com lookalike");

// unrelated domain is not flagged
assert.strictEqual(detectTyposquatting("my-personal-blog.dev"), null);

// full pipeline: safe HTTPS domain scores low
const safe = analyzeUrl("https://example.com/");
assert.strictEqual(scoreToStatus(safe.score), "safe");

// full pipeline: phishing-shaped URL scores high and includes the brand-impersonation signal
const phishy = analyzeUrl("http://paypa1.com/verify-account-login");
assert.ok(phishy.score > 60, `expected high score, got ${phishy.score}`);
assert.ok(phishy.riskFactors.some((f) => f.includes("typosquatting")));

console.log("test_analyzer.js: all checks passed");
