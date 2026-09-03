import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compilePolicy, resetCompiler } from "../build/wasm/index.mjs";

async function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const vectorRoot = path.join(root, "tests", "vectors");
  const sources = (await readdir(vectorRoot)).filter((name) => name.endsWith(".source.json"));

  for (const sourceName of sources) {
    const stem = sourceName.slice(0, -".source.json".length);
    const source = await readFile(path.join(vectorRoot, sourceName), "utf8");
    const expectedMir = await readFile(path.join(vectorRoot, `${stem}.mir`));
    const expectedDigest = (await readFile(path.join(vectorRoot, `${stem}.sha256`), "utf8")).trim();
    const expectedInspection = await readFile(path.join(vectorRoot, `${stem}.inspect.json`), "utf8");
    const actual = await compilePolicy(source);
    assert.deepEqual(Buffer.from(actual.mir), expectedMir, `${stem}: MIR bytes`);
    assert.equal(actual.digest, expectedDigest, `${stem}: decision digest`);
    assert.equal(actual.inspection, expectedInspection, `${stem}: inspection JSON`);
  }

  await resetCompiler();
  console.log(`verified ${sources.length} native/WASM conformance vectors`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
