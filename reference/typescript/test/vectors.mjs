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
