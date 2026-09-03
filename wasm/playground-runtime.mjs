import { verifyMirV3Digest } from "./mir-v3.js";

async function compileAndVerify(source) {
  /*
   * Keep the public browser bridge available while the Emscripten runtime is
   * fetched and instantiated.  The generated module is deliberately loaded
   * only when compilation is requested: slow WASM startup must never leave the
   * editor looking ready while its API is still absent.
   */
  const { compilePolicy } = await import("./index.mjs");
  const compiled = await compilePolicy(source);
  const verified = await verifyMirV3Digest(compiled.mir, compiled.digest);
  return {
    ...compiled,
    verifiedDigest: verified.digest,
    policy: verified.policy,
  };
}

globalThis.MaelysPolicyPlayground = { compileAndVerify };
globalThis.dispatchEvent(new Event("maelys-policy-playground-ready"));

export { compileAndVerify };
