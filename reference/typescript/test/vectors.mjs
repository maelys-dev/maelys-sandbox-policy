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

const valid = new Uint8Array(await readFile(path.join(vectorRoot, artifacts[0])));
const invalid = new Uint8Array(valid.length + 1);
invalid.set(valid);
await assert.rejects(() => verifyMirV3Digest(invalid), /invalid canonical MIR v3/);
console.log(`verified ${artifacts.length} MIR v3 vectors with the TypeScript reference verifier`);
