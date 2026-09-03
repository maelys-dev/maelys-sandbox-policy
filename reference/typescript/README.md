# MIR v3 reference verifier

This dependency-free TypeScript module verifies the structure and canonical
ordering of a Maelys MIR v3 artifact, then computes its decision digest with
Web Crypto. It does not compile policy source and does not define policy
identity. The C implementation remains the normative producer of canonical MIR
bytes.

```ts
import { verifyMirV3Digest } from "@maelys/mir-v3-verifier";

const bytes = new Uint8Array(await (await fetch("policy.mir")).arrayBuffer());
const { policy, digest } = await verifyMirV3Digest(bytes);
```
