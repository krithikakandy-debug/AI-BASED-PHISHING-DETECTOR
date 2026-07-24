const assert = require("assert");
const { pgAppendAuditEntry, pgVerifyChain } = require("./hashchain");

(async () => {
  let log = [];
  log.push(await pgAppendAuditEntry(log, { url: "https://a.com", score: 0, status: "safe", riskFactors: [] }));
  log.push(await pgAppendAuditEntry(log, { url: "http://b.com", score: 90, status: "dangerous", riskFactors: ["x"] }));

  assert.strictEqual(await pgVerifyChain(log), true, "untouched chain should verify");

  const tampered = JSON.parse(JSON.stringify(log));
  tampered[0].score = 0; // still 0, so mutate something visible instead
  tampered[1].score = 5; // attacker lowers a dangerous score after the fact
  assert.strictEqual(await pgVerifyChain(tampered), false, "tampered entry should fail verification");

  const truncated = [log[1]]; // dropping an earlier entry breaks prevHash linkage
  assert.strictEqual(await pgVerifyChain(truncated), false, "truncated chain should fail verification");

  console.log("test_hashchain.js: all checks passed");
})();
