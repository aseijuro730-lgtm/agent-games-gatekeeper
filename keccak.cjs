// Minimal pure-JS Keccak-256 (original Keccak padding, NOT SHA3).
// Used ONLY for the optional TASKID_ENCODING=keccak taskId mapping.
// Self-tests against known vectors on load; throws if broken.
"use strict";

const MASK = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const R = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2,
  61, 56, 14,
];
function rot(x, n) {
  return n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK;
}
function keccakF(state) {
  for (let round = 0; round < 24; round++) {
    const C = new Array(5);
    for (let x = 0; x < 5; x++)
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    const D = new Array(5);
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= D[x];
    const B = new Array(25);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rot(state[x + 5 * y], R[x + 5 * y]);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        state[x + 5 * y] =
          (B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y])) & MASK;
    state[0] ^= RC[round];
  }
}

function keccak256(input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const rate = 136;
  const state = new Array(25).fill(0n);
  let offset = 0;
  const paddedLen = Math.floor((data.length + rate) / rate) * rate;
  const padded = Buffer.alloc(paddedLen);
  data.copy(padded);
  padded[data.length] ^= 0x01;
  padded[paddedLen - 1] ^= 0x80;
  while (offset < paddedLen) {
    const block = padded.subarray(offset, offset + rate);
    for (let i = 0; i < 17; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++)
        lane |= BigInt(block[i * 8 + b]) << BigInt(8 * b);
      state[i] ^= lane;
    }
    keccakF(state);
    offset += rate;
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}
function keccak256Hex(input) {
  return keccak256(input).toString("hex");
}

// Self-test (known vectors) — fail loudly if the implementation is wrong.
if (
  keccak256Hex("") !==
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" ||
  keccak256Hex("abc") !==
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
) {
  throw new Error("keccak256 self-test FAILED");
}

module.exports = { keccak256, keccak256Hex };
