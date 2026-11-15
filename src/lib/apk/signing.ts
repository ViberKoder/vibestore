import { createHash } from "crypto";

/**
 * APK signature facts without cryptographic verification:
 *  - v1: META-INF/*.RSA|DSA|EC (JAR signing)
 *  - v2/v3: APK Signing Block, magic "APK Sig Block 42", just before the central directory
 * Debug keys are recognised by the "Android Debug" common name in the certificate bytes.
 */
const EOCD_SIG = 0x06054b50;
const SIG_MAGIC = Buffer.from("APK Sig Block 42", "ascii");
const ID_V2 = 0x7109871a;
const ID_V3 = 0xf05368c0;
const ID_V31 = 0x1b93ad61;

export interface SigningFacts {
  v1: boolean;
  v2: boolean;
  v3: boolean;
  debugKey: boolean;
  /** Fingerprint of the v1 signature file, for pinning the signer across versions */
  signerDigest?: string;
  blockIds: number[];
}

export function signingFacts(buf: Buffer, v1Files: Array<{ name: string; bytes: Buffer }>): SigningFacts {
  const facts: SigningFacts = { v1: v1Files.length > 0, v2: false, v3: false, debugKey: false, blockIds: [] };
  for (const f of v1Files) {
    if (f.bytes.includes(Buffer.from("Android Debug", "utf8"))) facts.debugKey = true;
  }
  if (v1Files[0]) facts.signerDigest = createHash("sha256").update(v1Files[0].bytes).digest("hex");

  // Locate the end of central directory to find the signing block just before it.
  const searchFrom = Math.max(0, buf.length - (65535 + 22));
  let eocd = -1;
  for (let i = buf.length - 22; i >= searchFrom; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return facts;
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset < 32 || cdOffset > buf.length) return facts;
  const magicAt = cdOffset - 16;
  if (!buf.subarray(magicAt, magicAt + 16).equals(SIG_MAGIC)) return facts;

  const blockSize = Number(buf.readBigUInt64LE(cdOffset - 24));
  const start = cdOffset - blockSize - 8;
  if (start < 0 || blockSize < 24) return facts;
  let p = start + 8;
  const end = cdOffset - 24;
  while (p + 12 <= end) {
    const len = Number(buf.readBigUInt64LE(p));
    const id = buf.readUInt32LE(p + 8);
    facts.blockIds.push(id);
    if (id === ID_V2) facts.v2 = true;
    if (id === ID_V3 || id === ID_V31) facts.v3 = true;
    if (id === ID_V2 || id === ID_V3 || id === ID_V31) {
      if (buf.subarray(p, p + 8 + len).includes(Buffer.from("Android Debug", "utf8"))) facts.debugKey = true;
    }
    p += 8 + len;
    if (len <= 0) break;
  }
  return facts;
}
