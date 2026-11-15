// Test harness: boots the server on a test port with a test secret, runs
// preflight + all trap/valid cases + replay + reuse + bad-signature checks,
// and independently re-verifies every attached Groth16 proof with snarkjs.
"use strict";
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const TEST_SECRET = "test-hmac-secret-32-bytes-minimum-length-ok";
const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const DATA_DIR = "/tmp/gk-test-data";
const VK = JSON.parse(
  fs.readFileSync(path.join(__dirname, "circuits", "verification_key.json"), "utf8")
);

const VK1 = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK2 = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b1";
const ADDR1 = "0xDe42a7b8f3e2c19d4a6b5c7d8e9f0a1b2c3d4e5f6";
const ADDR2 = "0xDe42a7b8f3e2c19d4a6b5c7d8e9f0a1b2c3d4e5f7";

function signHex(bodyStr, secret = TEST_SECRET) {
  return crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(bodyStr).digest("hex");
}
async function post(obj, { sign = true, secret = TEST_SECRET, rawHeader = null } = {}) {
  const bodyStr = typeof obj === "string" ? obj : JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = rawHeader || signHex(bodyStr, secret);
  const t0 = Date.now();
  const res = await fetch(BASE + "/agent", { method: "POST", headers, body: bodyStr });
  const text = await res.text();
  return { status: res.status, text, ms: Date.now() - t0, sig: res.headers.get("x-agent-games-signature") };
}
function taskEnvelope(taskId, input, mode = "practice") {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode,
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  };
}
function validInput(over = {}) {
  return {
    registered_vk: VK1, proof_vk: VK1,
    minimum: "1000", public_balance: "1460",
    expiry_block: 8430000, current_block: 8420000,
    recipient: ADDR1, condition_recipient: ADDR1,
    amount: "500", max_transfer: "1000",
    proof_tx: "0xaaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
    ...over,
  };
}
async function verifyAttachedProof(parsed, label) {
  if (!parsed.proof || !parsed.public_signals) return "NO-PROOF";
  const ok = await snarkjs.groth16.verify(VK, parsed.public_signals, parsed.proof);
  return ok ? "PROOF-OK" : "PROOF-INVALID";
}
function checkRespSig(text, sig) {
  return sig === signHex(text);
}

let failures = 0;
function expect(cond, label) {
  console.log(`${cond ? "PASS" : "FAIL"} ${label}`);
  if (!cond) failures++;
}

(async () => {
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
  const server = spawn("node", ["server.cjs"], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(PORT),
      DATA_DIR,
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stdout.on("data", (d) => (serverLog += d.toString()));
  server.stderr.on("data", (d) => (serverLog += d.toString()));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  try {
    // Wait for boot.
    for (let i = 0; i < 30; i++) {
      try {
        const r = await fetch(BASE + "/health");
        if (r.status === 200) break;
      } catch (_) {}
      await sleep(500);
    }
    await sleep(2500); // let warm-up finish

    // 1. Health GET
    {
      const r = await fetch(BASE + "/health");
      const j = await r.json();
      expect(r.status === 200 && j.ok === true, "GET /health -> 200 ok");
    }
    // 2. Preflight
    {
      const r = await post({ type: "agent-games.preflight.v1" });
      const j = JSON.parse(r.text);
      expect(r.status === 200 && j.ok === true && j.protocolVersion === "v1", "preflight -> ok/v1");
      expect(checkRespSig(r.text, r.sig), "preflight response signature valid");
    }
    // 3. VK_SUBSTITUTION (sample shape from event page, full hashes)
    let vkResp;
    {
      const r = await post(taskEnvelope("gk_test_vk", validInput({ proof_vk: VK2 })));
      const j = JSON.parse(r.text);
      vkResp = r.text;
      expect(r.status === 200 && j.decision === "REJECT" && j.reason_code === "VK_SUBSTITUTION",
        `VK_SUBSTITUTION -> REJECT (${r.ms}ms)`);
      expect((await verifyAttachedProof(j)) === "PROOF-OK", "VK_SUBSTITUTION proof verifies");
      expect(checkRespSig(r.text, r.sig), "VK_SUBSTITUTION response signature valid");
      expect(r.ms < 15000, `VK_SUBSTITUTION latency ${r.ms}ms < 15s`);
    }
    // 4. VALID -> APPROVE
    let validBody;
    {
      const r = await post(taskEnvelope("gk_test_valid", validInput({
        proof_tx: "0xbbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
      })));
      const j = JSON.parse(r.text);
      validBody = r.text;
      expect(r.status === 200 && j.decision === "APPROVE" && j.reason_code === "VALID_CONDITION",
        `VALID -> APPROVE (${r.ms}ms)`);
      expect((await verifyAttachedProof(j)) === "PROOF-OK", "VALID proof verifies");
      expect(checkRespSig(r.text, r.sig), "VALID response signature valid");
    }
    // 5. Replay same task_id -> identical body
    {
      const r = await post(taskEnvelope("gk_test_valid", validInput({
        proof_tx: "0xbbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
      })));
      expect(r.text === validBody, "replay task_id -> identical cached response");
    }
    // 6. Reused proof_tx, new task_id -> PROOF_REUSED, no proof
    {
      const r = await post(taskEnvelope("gk_test_reuse", validInput({
        proof_tx: "0xbbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
      })));
      const j = JSON.parse(r.text);
      expect(r.status === 200 && j.decision === "REJECT" && j.reason_code === "PROOF_REUSED",
        "reused proof_tx -> REJECT/PROOF_REUSED");
      expect(!j.proof && !j.public_signals, "PROOF_REUSED -> no proof attached (excluded)");
    }
    // 7. Other traps
    const traps = [
      ["THRESHOLD_MISMATCH", { public_balance: "999" }],
      ["EXPIRED_CONDITION", { current_block: 8430000 }],
      ["RECIPIENT_MISMATCH", { recipient: ADDR2 }],
      ["AMOUNT_OVERFLOW", { amount: "1001" }],
    ];
    for (const [code, over] of traps) {
      const tx = "0xcccc" + Buffer.from(code).toString("hex").slice(0, 56).padEnd(56, "0");
      const r = await post(taskEnvelope("gk_test_" + code.toLowerCase(), validInput({ ...over, proof_tx: tx })));
      const j = JSON.parse(r.text);
      expect(r.status === 200 && j.decision === "REJECT" && j.reason_code === code, `${code} -> REJECT`);
      expect((await verifyAttachedProof(j)) === "PROOF-OK", `${code} proof verifies`);
    }
    // 8. Bad signature / missing signature
    {
      const r = await post(taskEnvelope("gk_test_badsig", validInput()), { rawHeader: "0".repeat(64) });
      expect(r.status === 401, "bad signature -> 401");
    }
    {
      const r = await post(taskEnvelope("gk_test_nosig", validInput()), { sign: false });
      expect(r.status === 401, "missing signature -> 401");
    }
    // 9. String task_id (real format "gk_24_9d1") with utf8 encoding
    {
      const r = await post(taskEnvelope("gk_24_9d1", validInput({
        proof_tx: "0xdddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333",
      })));
      const j = JSON.parse(r.text);
      expect(r.status === 200 && j.decision === "APPROVE", "string task_id gk_24_9d1 -> APPROVE");
      expect((await verifyAttachedProof(j)) === "PROOF-OK", "string task_id proof verifies");
    }
    // 10. Persistence: restart server, replay must still hit cache + reuse must persist
    server.kill("SIGTERM");
    await sleep(1500);
    const server2 = spawn("node", ["server.cjs"], {
      cwd: __dirname,
      env: { ...process.env, PORT: String(PORT), DATA_DIR, AGENT_GAMES_HMAC_SECRET: TEST_SECRET },
      stdio: ["ignore", "pipe", "pipe"],
    });
    server2.stdout.on("data", (d) => (serverLog += d.toString()));
    server2.stderr.on("data", (d) => (serverLog += d.toString()));
    for (let i = 0; i < 30; i++) {
      try {
        const r = await fetch(BASE + "/health");
        if (r.status === 200) break;
      } catch (_) {}
      await sleep(500);
    }
    {
      const r = await post(taskEnvelope("gk_test_valid", validInput({
        proof_tx: "0xbbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
      })));
      expect(r.text === validBody, "after restart: replay still cached");
      const r2 = await post(taskEnvelope("gk_test_reuse2", validInput({
        proof_tx: "0xbbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
      })));
      const j2 = JSON.parse(r2.text);
      expect(j2.reason_code === "PROOF_REUSED", "after restart: seen-set persisted");
    }
    server2.kill("SIGTERM");
    await sleep(800);
  } finally {
    try { server.kill("SIGKILL"); } catch (_) {}
  }
  console.log(failures === 0 ? "ALL TESTS PASSED" : `${failures} TEST(S) FAILED`);
  if (failures > 0) console.log("--- server log ---\n" + serverLog.slice(-3000));
  process.exit(failures === 0 ? 0 : 1);
})();
