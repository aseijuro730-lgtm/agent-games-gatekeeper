# Gatekeeper Agent — zkVerify Agent Games, Season 01

A Proof Gatekeeper agent for [Agent Games](https://agentgames.zkverify.io)
(Season 01, 21 Oct – 21 Nov 2026). It receives signed proof-backed transfer
tasks at a public HTTPS endpoint, checks every field of the condition,
answers APPROVE/REJECT with a reason code, and attaches a locally generated
Groth16 proof (official gatekeeper circuit, verified against the platform's
registered key).

## How it decides

Checks run in order; the first failure decides the rejection. Malformed
input fails closed to `REJECT / VK_SUBSTITUTION`.

| # | Check | Reject reason |
|---|-------|---------------|
| 1 | Proof VK matches the registered condition VK | `VK_SUBSTITUTION` |
| 2 | Public balance >= condition minimum | `THRESHOLD_MISMATCH` |
| 3 | Proof reference not seen before (persistent seen-set) | `PROOF_REUSED` |
| 4 | `current_block < expiry_block` | `EXPIRED_CONDITION` |
| 5 | Recipient matches the condition recipient | `RECIPIENT_MISMATCH` |
| 6 | Amount <= single-transfer cap | `AMOUNT_OVERFLOW` |
| — | All pass | `APPROVE / VALID_CONDITION` |

Boundaries are circuit-confirmed: balance equal to the minimum passes, amount
equal to the cap passes, `current_block >= expiry_block` is expired.

Every response is `{ decision, reason_code, proof, public_signals }`
(`proof_tx` echoed when present), signed with `x-agent-games-signature`
(HMAC-SHA256 over the raw body). Incoming requests must carry a valid
`x-agent-games-signature` over the raw body, verified **before** parsing.
`task_id` is an idempotency key: retries get a byte-identical cached
response. `PROOF_REUSED` answers carry no proof (the platform excludes them).

## Proof generation

Groth16/BN128 via `snarkjs`, using the official artifacts from
`/api/circuit-info` (`vkHash 0x6b79c6…d77b0`). Proof time is ~300–400 ms
warm (~1 s cold), far under the 60 s response deadline. Every proof is
re-verified locally before sending; if proving fails, the decision is still
returned without a proof.

String task IDs (e.g. `gk_24_9d1`) are encoded to field elements with
`TASKID_ENCODING=utf8` by default (`keccak` and `numeric` modes available).
A wrong encoding risks only the reliability bonus, never the decision score.

## Run it

```sh
npm install
npm run setup        # downloads + hash-verifies gatekeeper.wasm / .zkey
export AGENT_GAMES_HMAC_SECRET='<one-time secret from agent registration>'
npm start            # listens on PORT (default 8787)
```

`npm test` runs the 27-case suite (all 7 decision cases with independently
re-verified proofs, replay/idempotency, reuse detection, bad-signature
rejection, restart persistence).

## Deploy

`Dockerfile` + `fly.toml` included for Fly.io (free tier works; keep
`auto_stop_machines = false` — a sleeping agent forfeits tasks). Set the
HMAC secret with `fly secrets set AGENT_GAMES_HMAC_SECRET=...`, then register
the `https://<app>.fly.dev/agent` URL in the Agent Games dashboard, run the
signed preflight, and complete at least one practice task before a scored
round opens.

## Files

- `server.cjs` — the agent (Node stdlib + snarkjs only, no secrets in code)
- `keccak.cjs` — pure-JS keccak for the `keccak` task-ID encoding mode
- `test.cjs` — 27-case test suite
- `circuits/verification_key.json` — exported verification key (13 public inputs)
- `scripts/download-artifacts.sh` — fetches + verifies the .wasm/.zkey
