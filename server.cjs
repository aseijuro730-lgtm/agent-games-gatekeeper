// Proof Gatekeeper competition agent — zkVerify Agent Games Season 01.
// Deterministic 7-check decision logic + local Groth16 proofs (snarkjs) + HMAC.
// No secrets in this file. Secret via env AGENT_GAMES_HMAC_SECRET or 0600 file.
"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const ROOT = __dirname;
const PORT = parseInt(process.env.PORT || "8787", 10);
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const HMAC_SECRET_FILE =
  process.env.HMAC_SECRET_FILE || path.join(DATA_DIR, "hmac-secret");
const TASKID_ENCODING = (process.env.TASKID_ENCODING || "utf8").toLowerCase();
const PROOF_TIMEOUT_MS = parseInt(process.env.PROOF_TIMEOUT_MS || "45000", 10);
const MAX_BODY = 1024 * 1024;

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = path.join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(ROOT, "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(ROOT, "circuits", "verification_key.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
const SEEN_PATH = path.join(DATA_DIR, "seen.json");
const RESP_PATH = path.join(DATA_DIR, "responses.json");
const LOG_PATH = path.join(DATA_DIR, "agent.log");

let VK = null;
let keccak = null;
if (TASKID_ENCODING === "keccak") keccak = require("./keccak.cjs");

// ---------------------------------------------------------------- logging
function log(obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...obj });
  console.log(line);
  try {
    if (fs.existsSync(LOG_PATH) && fs.statSync(LOG_PATH).size > 5 * 1024 * 1024)
      fs.renameSync(LOG_PATH, LOG_PATH + ".1");
    fs.appendFileSync(LOG_PATH, line + "\n");
  } catch (_) {}
}

// ---------------------------------------------------------------- state
function loadJson(p, fallback) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (_) {
    return fallback;
  }
}
function saveJsonAtomic(p, value) {
  const tmp = p + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value));
  fs.renameSync(tmp, p);
}
const seenSet = new Set(loadJson(SEEN_PATH, [])); // proof_tx (lowercase)
const responses = new Map(Object.entries(loadJson(RESP_PATH, {}))); // task_id -> body string
function persistSeen() {
  saveJsonAtomic(SEEN_PATH, [...seenSet]);
}
function persistResponses() {
  saveJsonAtomic(RESP_PATH, Object.fromEntries(responses));
}

// ---------------------------------------------------------------- HMAC secret (re-read file per request; env at boot)
let envSecret = (process.env.AGENT_GAMES_HMAC_SECRET || "").trim() || null;
let fileSecretCache = { mtime: 0, value: null };
function getSecret() {
  if (envSecret) return envSecret;
  try {
    const st = fs.statSync(HMAC_SECRET_FILE);
    if (st.mtimeMs !== fileSecretCache.mtime) {
      fileSecretCache = {
        mtime: st.mtimeMs,
        value: fs.readFileSync(HMAC_SECRET_FILE, "utf8").trim() || null,
      };
    }
    return fileSecretCache.value;
  } catch (_) {
    return null;
  }
}
function candidateKeys(secret) {
  const keys = [Buffer.from(secret, "utf8")];
  if (/^[0-9a-fA-F]{64}$/.test(secret)) keys.push(Buffer.from(secret, "hex"));
  return keys;
}
// Returns the key Buffer that verified, or null. Header may be hex or base64.
function verifySignature(rawBody, header, secret) {
  if (!header || !secret) return null;
  const h = String(header).trim();
  const candidates = [];
  if (/^[0-9a-fA-F]{64}$/.test(h)) candidates.push(Buffer.from(h, "hex"));
  try {
    const b = Buffer.from(h, "base64");
    if (b.length === 32) candidates.push(b);
  } catch (_) {}
  if (!candidates.length) return null;
  for (const key of candidateKeys(secret)) {
    const mac = crypto.createHmac("sha256", key).update(rawBody).digest();
    for (const c of candidates) {
      if (c.length === 32 && crypto.timingSafeEqual(mac, c)) return key;
    }
  }
  return null;
}
function signBody(rawBody, key) {
  return crypto.createHmac("sha256", key).update(rawBody).digest("hex");
}

// ---------------------------------------------------------------- field parsing
function toBig(v, field) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0) throw new Error("bad " + field);
    return BigInt(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^\d+$/.test(s)) return BigInt(s);
  }
  throw new Error("bad " + field);
}
function normHex(v) {
  const s = String(v).trim().toLowerCase();
  return s.startsWith("0x") ? s : "0x" + s;
}
function pick(input, snake, camel) {
  if (input[snake] !== undefined) return input[snake];
  if (input[camel] !== undefined) return input[camel];
  return undefined;
}

// ---------------------------------------------------------------- taskId encoding
function encodeTaskId(taskId) {
  const s = String(taskId);
  if (/^\d+$/.test(s)) return (BigInt(s) % P).toString();
  if (TASKID_ENCODING === "keccak") {
    return (BigInt("0x" + keccak.keccak256Hex(s)) % P).toString();
  }
  // default: utf8 bytes -> bigint mod p
  return (BigInt("0x" + Buffer.from(s, "utf8").toString("hex")) % P).toString();
}

// ---------------------------------------------------------------- decision logic (matches circuit exactly)
function decide(input) {
  const raw = {
    registered_vk: pick(input, "registered_vk", "registeredVk"),
    proof_vk: pick(input, "proof_vk", "proofVk"),
    minimum: pick(input, "minimum", "minimum"),
    public_balance: pick(input, "public_balance", "publicBalance"),
    expiry_block: pick(input, "expiry_block", "expiryBlock"),
    current_block: pick(input, "current_block", "currentBlock"),
    recipient: pick(input, "recipient", "recipient"),
    condition_recipient: pick(input, "condition_recipient", "conditionRecipient"),
    amount: pick(input, "amount", "amount"),
    max_transfer: pick(input, "max_transfer", "maxTransfer"),
    proof_tx: pick(input, "proof_tx", "proofTx"),
  };
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined || v === null || v === "") {
      return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", malformed: k, raw };
    }
  }
  let nums;
  try {
    nums = {
      registeredVkHash: toBig(raw.registered_vk, "registered_vk"),
      proofVkHash: toBig(raw.proof_vk, "proof_vk"),
      minimum: toBig(raw.minimum, "minimum"),
      publicBalance: toBig(raw.public_balance, "public_balance"),
      expiryBlock: toBig(raw.expiry_block, "expiry_block"),
      currentBlock: toBig(raw.current_block, "current_block"),
      recipient: toBig(raw.recipient, "recipient"),
      conditionRecipient: toBig(raw.condition_recipient, "condition_recipient"),
      amount: toBig(raw.amount, "amount"),
      maxTransfer: toBig(raw.max_transfer, "max_transfer"),
    };
  } catch (e) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", malformed: e.message, raw };
  }
  const proofTx = normHex(raw.proof_tx);
  // Check order: VK -> threshold -> reuse -> expiry -> recipient -> amount.
  if (normHex(raw.registered_vk) !== normHex(raw.proof_vk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", nums, proofTx };
  if (nums.publicBalance < nums.minimum)
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", nums, proofTx };
  if (seenSet.has(proofTx))
    return { decision: "REJECT", reason_code: "PROOF_REUSED", nums, proofTx };
  if (nums.currentBlock >= nums.expiryBlock)
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", nums, proofTx };
  if (normHex(raw.recipient) !== normHex(raw.condition_recipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", nums, proofTx };
  if (nums.amount > nums.maxTransfer)
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", nums, proofTx };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", nums, proofTx };
}

// ---------------------------------------------------------------- proving (serialized queue)
let proveChain = Promise.resolve();
function enqueueProve(fn) {
  const run = proveChain.then(fn, fn);
  proveChain = run.then(
    () => {},
    () => {}
  );
  return run;
}
async function generateProof(taskId, decision, nums) {
  const salt = BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString();
  const input = {
    registeredVkHash: nums.registeredVkHash.toString(),
    proofVkHash: nums.proofVkHash.toString(),
    minimum: nums.minimum.toString(),
    publicBalance: nums.publicBalance.toString(),
    expiryBlock: nums.expiryBlock.toString(),
    currentBlock: nums.currentBlock.toString(),
    recipient: nums.recipient.toString(),
    conditionRecipient: nums.conditionRecipient.toString(),
    amount: nums.amount.toString(),
    maxTransfer: nums.maxTransfer.toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: encodeTaskId(taskId),
    salt,
  };
  const timeout = new Promise((_, rej) =>
    setTimeout(() => rej(new Error("proof timeout")), PROOF_TIMEOUT_MS)
  );
  const { proof, publicSignals } = await Promise.race([
    snarkjs.groth16.fullProve(input, WASM, ZKEY),
    timeout,
  ]);
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  if (!ok) throw new Error("local proof verify failed");
  return { proof, public_signals: publicSignals };
}

// ---------------------------------------------------------------- request handling
function isPreflight(body) {
  if (!body || typeof body !== "object") return false;
  if (body.preflight === true) return true;
  const t = String(body.type || "").toLowerCase();
  return t.includes("preflight") || t === "ping" || t === "health";
}
function isTask(body) {
  return (
    body &&
    typeof body === "object" &&
    typeof body.task_id === "string" &&
    body.input &&
    typeof body.input === "object"
  );
}

async function handleTask(body, key) {
  const taskId = body.task_id;
  const t0 = Date.now();
  if (responses.has(taskId)) {
    const cached = responses.get(taskId);
    log({ kind: "replay", task_id: taskId, ms: Date.now() - t0 });
    return { status: 200, body: cached, key };
  }
  const result = decide(body.input);
  // Record proof reference for reuse detection (all processed tasks).
  if (result.proofTx && !seenSet.has(result.proofTx)) {
    seenSet.add(result.proofTx);
    persistSeen();
  }
  const resp = {
    decision: result.decision,
    reason_code: result.reason_code,
    proof_tx: result.proofTx || String(body.input.proof_tx || body.input.proofTx || ""),
  };
  let proofAttached = false;
  let proofError = null;
  if (result.reason_code !== "PROOF_REUSED" && result.nums) {
    try {
      const { proof, public_signals } = await enqueueProve(() =>
        generateProof(taskId, result.decision, result.nums)
      );
      resp.proof = proof;
      resp.public_signals = public_signals;
      proofAttached = true;
    } catch (e) {
      proofError = String(e.message || e).slice(0, 200);
    }
  }
  const bodyStr = JSON.stringify(resp);
  responses.set(taskId, bodyStr);
  persistResponses();
  log({
    kind: "task",
    task_id: taskId,
    mode: body.mode || null,
    decision: result.decision,
    reason_code: result.reason_code,
    malformed: result.malformed || null,
    proof: proofAttached,
    proof_error: proofError,
    ms: Date.now() - t0,
  });
  return { status: 200, body: bodyStr, key };
}

function handlePreflight(key) {
  const bodyStr = JSON.stringify({ ok: true, protocolVersion: "v1" });
  return { status: 200, body: bodyStr, key };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" || req.method === "HEAD") {
      const bodyStr = JSON.stringify({
        ok: true,
        service: "agentgames-gatekeeper",
        protocolVersion: "v1",
        time: new Date().toISOString(),
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(req.method === "HEAD" ? "" : bodyStr);
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "method not allowed" }));
      return;
    }
    // Read raw body FIRST (HMAC is over raw bytes).
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > MAX_BODY) {
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "body too large" }));
        return;
      }
      chunks.push(c);
    }
    const rawBody = Buffer.concat(chunks);
    const secret = getSecret();
    if (!secret) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "hmac secret not configured" }));
      log({ kind: "no-secret", path: req.url });
      return;
    }
    const key = verifySignature(rawBody, req.headers["x-agent-games-signature"], secret);
    if (!key) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "bad signature" }));
      log({ kind: "bad-signature", path: req.url });
      return;
    }
    let body;
    try {
      body = JSON.parse(rawBody.toString("utf8"));
    } catch (_) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "invalid json" }));
      return;
    }
    let out;
    if (isTask(body)) out = await handleTask(body, key);
    else {
      // Preflight handshake or unknown POST shape -> preflight response.
      if (!isPreflight(body))
        log({ kind: "unknown-post", path: req.url, keys: Object.keys(body || {}) });
      out = handlePreflight(key);
    }
    const sig = signBody(Buffer.from(out.body, "utf8"), out.key);
    res.writeHead(out.status, {
      "content-type": "application/json",
      "x-agent-games-signature": sig,
    });
    res.end(out.body);
  } catch (e) {
    log({ kind: "error", error: String(e.message || e).slice(0, 300) });
    try {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "internal error" }));
    } catch (_) {}
  }
});

function shutdown(signal) {
  log({ kind: "shutdown", signal });
  persistSeen();
  persistResponses();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// ---------------------------------------------------------------- boot
VK = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
server.listen(PORT, "127.0.0.1", () => {
  log({
    kind: "boot",
    port: PORT,
    data_dir: DATA_DIR,
    taskid_encoding: TASKID_ENCODING,
    secret_configured: !!getSecret(),
    seen_count: seenSet.size,
    cached_responses: responses.size,
    vk_nPublic: VK.nPublic,
  });
  // Background warm-up: one dummy proof so the first real task is fast.
  setTimeout(() => {
    const t0 = Date.now();
    enqueueProve(async () => {
      try {
        const nums = {
          registeredVkHash: 1n, proofVkHash: 1n, minimum: 1n, publicBalance: 2n,
          expiryBlock: 10n, currentBlock: 9n, recipient: 1n, conditionRecipient: 1n,
          amount: 1n, maxTransfer: 2n,
        };
        await generateProof("warmup", "APPROVE", nums);
        log({ kind: "warmup", ms: Date.now() - t0, ok: true });
      } catch (e) {
        log({ kind: "warmup", ms: Date.now() - t0, ok: false, error: String(e.message || e).slice(0, 200) });
      }
    });
  }, 500);
});
