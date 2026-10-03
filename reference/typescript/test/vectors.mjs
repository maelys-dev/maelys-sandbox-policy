import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyMirV3Digest } from "../dist/mir-v3.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const vectorRoot = path.join(root, "tests", "vectors");
const artifacts = (await readdir(vectorRoot)).filter((name) => name.endsWith(".mir"));

for (const artifact of artifacts) {
  const stem = artifact.slice(0, -4);
  const bytes = new Uint8Array(await readFile(path.join(vectorRoot, artifact)));
  const expected = (await readFile(path.join(vectorRoot, `${stem}.sha256`), "utf8")).trim();
  const { policy, digest } = await verifyMirV3Digest(bytes, expected);
  assert.equal(policy.formatVersion, 3);
  assert.equal(digest, expected);
}

const flagged = new Uint8Array(await readFile(path.join(vectorRoot, "mediated-flags.mir")));
const { policy: flaggedPolicy } = await verifyMirV3Digest(flagged);
assert.deepEqual(flaggedPolicy.network.allow, [
  { protocol: "tcp", host: "api.github.com", port: 443 },
  { protocol: "tcp", host: "cache.internal", port: 8080, allowPrivateAddresses: true },
  { protocol: "tcp", host: "github.com", port: 443, requireTlsSni: true },
  { protocol: "tcp", host: "registry.internal", port: 5000, requireTlsSni: true,
    allowPrivateAddresses: true },
]);
for (const [offset, value] of [[0x33 + 4, 0x04], [0x33 + 5, 0x01]]) {
  const tampered = flagged.slice();
  tampered[offset] = value;
  await assert.rejects(() => verifyMirV3Digest(tampered), /invalid canonical MIR v3/);
}

// A last label that reads as a number is a literal in disguise: bytes an
// earlier encoder could have written for registry.0x7f0001 or
// registry.00000001 (same length, same order) are refused.
for (const disguised of ["registry.0x7f0001", "registry.00000001"]) {
  const tampered = flagged.slice();
  tampered.set(new TextEncoder().encode(disguised), 0x69);
  await assert.rejects(() => verifyMirV3Digest(tampered), /non-canonical host/);
}

// A TLS server name is never required of a literal (RFC 6066): these bytes
// are the C encoder's for 127.0.0.1 with allowPrivateAddresses, the flags
// byte then set to requireTlsSni too; tests/test_mir.c holds the same hex.
const literalSni = Uint8Array.from(Buffer.from("4d4d495200030000000000000301010000000001020101bb030000093132372e302e302e31", "hex"));
await assert.rejects(() => verifyMirV3Digest(literalSni), /TLS server name required of a literal/);

const denyWrite = new Uint8Array(await readFile(path.join(vectorRoot, "deny-write.mir")));
const { policy: denyWritePolicy } = await verifyMirV3Digest(denyWrite);
assert.deepEqual(denyWritePolicy.filesystem.rules.map((rule) =>
  `${rule.access} ${rule.scope} ${rule.path}`), [
  "write exact ",
  "deny-write exact ",
  "write tree ",
  "deny-write tree .git",
  "deny tree secrets",
]);
// A deny-write before its grant, a deny beside a deny-write and a repeated
// grant are not canonical.
for (const [first, second] of [[4, 2], [3, 4], [2, 2]]) {
  const tampered = denyWrite.slice();
  tampered[21] = first;
  tampered[33] = second;
  await assert.rejects(() => verifyMirV3Digest(tampered), /invalid canonical MIR v3/);
}

const valid = new Uint8Array(await readFile(path.join(vectorRoot, artifacts[0])));
const invalid = new Uint8Array(valid.length + 1);
invalid.set(valid);
await assert.rejects(() => verifyMirV3Digest(invalid), /invalid canonical MIR v3/);
console.log(`verified ${artifacts.length} MIR v3 vectors with the TypeScript reference verifier`);
