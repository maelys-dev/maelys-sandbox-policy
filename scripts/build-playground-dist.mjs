import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(repository, "dist", "playground");
const version = (await readFile(path.join(repository, "VERSION"), "utf8")).trim();
const header = await readFile(path.join(repository, "include", "maelys", "mir.h"), "utf8");
const formatMatch = /^#define MAELYS_MIR_FORMAT_VERSION (\d+)u$/m.exec(header);
if (!version) throw new Error("VERSION is empty");
if (!formatMatch) throw new Error("MAELYS_MIR_FORMAT_VERSION is missing from mir.h");

const assets = [
  { source: "build/wasm/maelys-policy.wasm", name: "maelys-policy.wasm" },
  { source: "build/wasm/maelys-policy.mjs", name: "maelys-policy.mjs" },
  { source: "build/wasm/index.mjs", name: "index.mjs" },
  { source: "build/wasm/playground-runtime.mjs", name: "playground-runtime.mjs" },
  { source: "reference/typescript/dist/mir-v3.js", name: "mir-v3.js" },
];

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

const files = [];
for (const asset of assets) {
  const source = path.join(repository, asset.source);
  const metadata = await stat(source);
  if (!metadata.isFile()) throw new Error(`not a regular file: ${asset.source}`);
  const bytes = await readFile(source);
  await copyFile(source, path.join(output, asset.name));
  files.push({
    source: asset.name,
    target: `public/wasm/${asset.name}`,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

const manifest = {
  formatVersion: 1,
  product: "maelys-sandbox-policy",
  sourceVersion: version,
  mirFormatVersion: Number(formatMatch[1]),
  lockTarget: "public/wasm/assets.lock.json",
  files,
};
await writeFile(path.join(output, "assets.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
console.log(`built ${files.length} verified playground assets in ${path.relative(repository, output)}`);
