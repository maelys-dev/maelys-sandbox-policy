const MAX_BYTES = 1024 * 1024;
const MAX_RULES = 4096;
const MAX_PATH_BYTES = 4096;
const MAX_DESTINATIONS = 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });

export type FilesystemRule = {
  access: "read" | "write" | "deny";
  root: "minimal-runtime" | "workspace" | "temp" | "host";
  path: string;
  scope: "exact" | "tree";
  missing: "error" | "skip";
};

export type NetworkDestination = {
  protocol: "tcp";
  host: string;
  port: number;
};

export type VerifiedMirV3 = {
  formatVersion: 3;
  filesystem: { default: "deny"; rules: FilesystemRule[] };
  network: { mode: "none" | "direct" | "mediated"; allow: NetworkDestination[] };
  root: { mode: "read-only" | "ephemeral-write" };
  process: { treeConfinement: "required" | "disabled" };
};

type ParsedRule = FilesystemRule & {
  accessCode: number;
  rootCode: number;
  scopeCode: number;
  missingCode: number;
  pathBytes: Uint8Array;
};

type ParsedDestination = NetworkDestination & { hostBytes: Uint8Array };

function fail(message: string): never {
  throw new Error(`invalid canonical MIR v3: ${message}`);
}

function u16(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0) << 8) | (bytes[offset + 1] ?? 0);
}

function u32(bytes: Uint8Array, offset: number): number {
  return (((bytes[offset] ?? 0) * 0x1000000) +
    ((bytes[offset + 1] ?? 0) << 16) +
    ((bytes[offset + 2] ?? 0) << 8) +
    (bytes[offset + 3] ?? 0)) >>> 0;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const size = Math.min(left.length, right.length);
  for (let index = 0; index < size; index += 1) {
    const delta = (left[index] ?? 0) - (right[index] ?? 0);
    if (delta !== 0) return delta;
  }
  return left.length - right.length;
}

function normalizePath(root: number, value: string): string {
  const host = root === 4;
  if ((host && !value.startsWith("/")) || (!host && value.startsWith("/")))
    fail(host ? "host path is not absolute" : "symbolic-root path is absolute");
  const parts: string[] = [];
  for (const part of value.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") fail("parent path component");
    parts.push(part);
  }
  return host ? `/${parts.join("/")}` : parts.join("/");
}

function validDnsHost(host: string): boolean {
  if (host.length === 0 || host.length > 253 || host.startsWith(".") || host.endsWith("."))
    return false;
  return host.split(".").every((label) =>
    label.length > 0 && label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

function compareRule(left: ParsedRule, right: ParsedRule): number {
  if (left.rootCode !== right.rootCode) return left.rootCode - right.rootCode;
  const path = compareBytes(left.pathBytes, right.pathBytes);
  if (path !== 0) return path;
  if (left.scopeCode !== right.scopeCode) return left.scopeCode - right.scopeCode;
  if (left.missingCode !== right.missingCode) return left.missingCode - right.missingCode;
  return left.accessCode - right.accessCode;
}

function sameTarget(left: ParsedRule, right: ParsedRule): boolean {
  return left.rootCode === right.rootCode && left.scopeCode === right.scopeCode &&
    left.missingCode === right.missingCode && compareBytes(left.pathBytes, right.pathBytes) === 0;
}

function compareDestination(left: ParsedDestination, right: ParsedDestination): number {
  const host = compareBytes(left.hostBytes, right.hostBytes);
  return host !== 0 ? host : left.port - right.port;
}

export function verifyMirV3(input: Uint8Array): VerifiedMirV3 {
  const bytes = new Uint8Array(input);
  if (bytes.length < 20 || bytes.length > MAX_BYTES) fail("size outside limits");
  if (decoder.decode(bytes.subarray(0, 4)) !== "MMIR") fail("magic");
  if (u16(bytes, 4) !== 3 || u16(bytes, 6) !== 0) fail("version or flags");
  const rootModeCode = bytes[14] ?? 0;
  if (![1, 2].includes(rootModeCode) || (bytes[15] ?? 1) !== 0)
    fail("root mode or reserved header byte");

  const ruleCount = u32(bytes, 8);
  const networkCode = bytes[12] ?? 0;
  const processCode = bytes[13] ?? 2;
  const destinationCount = u32(bytes, 16);
  if (ruleCount > MAX_RULES || destinationCount > MAX_DESTINATIONS) fail("record limit");
  if (![1, 2, 3].includes(networkCode) || ![0, 1].includes(processCode)) fail("header values");
  if ((networkCode === 3) !== (destinationCount > 0)) fail("mediated allowlist shape");

  const accessNames = ["", "read", "write", "deny"] as const;
  const rootNames = ["", "minimal-runtime", "workspace", "temp", "host"] as const;
  const scopeNames = ["", "exact", "tree"] as const;
  const missingNames = ["", "error", "skip"] as const;
  let offset = 20;
  const rules: ParsedRule[] = [];
  for (let index = 0; index < ruleCount; index += 1) {
    if (bytes.length - offset < 12) fail(`truncated filesystem record ${index}`);
    const accessCode = bytes[offset + 1] ?? 0;
    const rootCode = bytes[offset + 2] ?? 0;
    const scopeCode = bytes[offset + 3] ?? 0;
    const missingCode = bytes[offset + 4] ?? 0;
    if ((bytes[offset] ?? 0) !== 1 || ![1, 2, 3].includes(accessCode) ||
        ![1, 2, 3, 4].includes(rootCode) || ![1, 2].includes(scopeCode) ||
        ![1, 2].includes(missingCode) || (bytes[offset + 5] ?? 1) !== 0 ||
        (bytes[offset + 6] ?? 1) !== 0 || (bytes[offset + 7] ?? 1) !== 0)
      fail(`filesystem record ${index}`);
    const size = u32(bytes, offset + 8);
    if (size > MAX_PATH_BYTES || bytes.length - offset - 12 < size)
      fail(`filesystem path ${index}`);
    const pathBytes = bytes.slice(offset + 12, offset + 12 + size);
    let path: string;
    try { path = decoder.decode(pathBytes); } catch { fail(`filesystem UTF-8 ${index}`); }
    if (path.includes("\0") || normalizePath(rootCode, path) !== path)
      fail(`non-canonical filesystem path ${index}`);
    const rule: ParsedRule = {
      access: accessNames[accessCode] as FilesystemRule["access"],
      root: rootNames[rootCode] as FilesystemRule["root"],
      path,
      scope: scopeNames[scopeCode] as FilesystemRule["scope"],
      missing: missingNames[missingCode] as FilesystemRule["missing"],
      accessCode, rootCode, scopeCode, missingCode, pathBytes,
    };
    const previous = rules.at(-1);
    if (previous && (compareRule(previous, rule) >= 0 || sameTarget(previous, rule)))
      fail(`filesystem order or duplicate target at ${index}`);
    rules.push(rule);
    offset += 12 + size;
  }

  const destinations: ParsedDestination[] = [];
  for (let index = 0; index < destinationCount; index += 1) {
    if (bytes.length - offset < 8 || (bytes[offset] ?? 0) !== 2 ||
        (bytes[offset + 1] ?? 0) !== 1) fail(`network record ${index}`);
    const port = u16(bytes, offset + 2);
    const size = u32(bytes, offset + 4);
    if (port === 0 || size === 0 || size > 253 || bytes.length - offset - 8 < size)
      fail(`network destination ${index}`);
    const hostBytes = bytes.slice(offset + 8, offset + 8 + size);
    let host: string;
    try { host = decoder.decode(hostBytes); } catch { fail(`network UTF-8 ${index}`); }
    if (!validDnsHost(host)) fail(`non-canonical host ${index}`);
    const destination: ParsedDestination = { protocol: "tcp", host, port, hostBytes };
    const previous = destinations.at(-1);
    if (previous && compareDestination(previous, destination) >= 0)
      fail(`network order or duplicate at ${index}`);
    destinations.push(destination);
    offset += 8 + size;
  }
  if (offset !== bytes.length) fail("trailing bytes");

  const cleanRules = rules.map(({ access, root, path, scope, missing }) =>
    ({ access, root, path, scope, missing }));
  const cleanDestinations = destinations.map(({ protocol, host, port }) =>
    ({ protocol, host, port }));
  return {
    formatVersion: 3,
    filesystem: { default: "deny", rules: cleanRules },
    network: {
      mode: (["", "none", "direct", "mediated"] as const)[networkCode] as
        VerifiedMirV3["network"]["mode"],
      allow: cleanDestinations,
    },
    root: { mode: rootModeCode === 2 ? "ephemeral-write" : "read-only" },
    process: { treeConfinement: processCode === 1 ? "required" : "disabled" },
  };
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function verifyMirV3Digest(bytes: Uint8Array, expected?: string) {
  const policy = verifyMirV3(bytes);
  const digest = await sha256Hex(bytes);
  if (expected && digest !== expected.replace(/^sha256:/, ""))
    fail("decision digest mismatch");
  return { policy, digest };
}
