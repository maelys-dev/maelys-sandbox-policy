import createMaelysPolicy from "./maelys-policy.mjs";

let modulePromise;

async function moduleOptions() {
  if (!globalThis.process?.versions?.node) return {};
  const [{ fileURLToPath }, path, { readFile }] = await Promise.all([
    import("node:url"),
    import("node:path"),
    import("node:fs/promises"),
  ]);
  /*
   * Ubuntu's packaged Emscripten still emits a Node branch which reads the
   * CommonJS __dirname global from an ES module.  Newer Emscripten uses
   * import.meta.url directly.  Supplying the equivalent global here keeps the
   * public ES-module facade portable across both generators; browsers never
   * enter this branch.
   */
  if (!("__dirname" in globalThis))
    globalThis.__dirname = path.dirname(fileURLToPath(import.meta.url));

  /* Older generators also mis-detect modern Node as a web runtime and try to
   * fetch() a file: URL.  Supplying the bytes makes instantiation independent
   * of that environment branch and is harmless for newer generators. */
  return {
    wasmBinary: await readFile(new URL("./maelys-policy.wasm", import.meta.url)),
  };
}

async function getModule() {
  modulePromise ??= moduleOptions().then((options) => createMaelysPolicy(options));
  return modulePromise;
}

export async function compilePolicy(source) {
  const module = await getModule();
  const code = module.ccall("maelys_wasm_compile_text", "number", ["string"], [source]);
  if (code !== 0) {
    const detail = module.UTF8ToString(module._maelys_wasm_error());
    throw new Error(detail || `MIR compiler failed with code ${code}`);
  }
  const hex = module.UTF8ToString(module._maelys_wasm_mir_hex());
  const mir = new Uint8Array(hex.length / 2);
  for (let index = 0; index < mir.length; index += 1)
    mir[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return {
    mir,
    digest: module.UTF8ToString(module._maelys_wasm_digest()),
    inspection: module.UTF8ToString(module._maelys_wasm_inspection()),
  };
}

export async function resetCompiler() {
  const module = await getModule();
  module._maelys_wasm_reset();
}
