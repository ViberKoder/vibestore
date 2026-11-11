/**
 * Structural inspection of ZIP-based packages (zip, jar, apk, ipa, docx-like)
 * without extracting anything. Reads only the central directory.
 */
export interface ArchiveEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  encrypted: boolean;
  symlink: boolean;
  method: number;
  /** Offset of this entry's local file header (for reading content). */
  localOffset: number;
  /** Extension says this is an executable or script. */
  executable?: boolean;
  /** Extension says this is another archive. */
  nested?: boolean;
}

export interface ArchiveReport {
  format: "zip" | "unsupported";
  reason?: string;
  entries: ArchiveEntry[];
  totalCompressed: number;
  totalUncompressed: number;
  zip64: boolean;
  truncated: boolean;
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const EXEC_EXT = /\.(exe|dll|scr|com|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|jar|sh|appimage|app|dmg|pkg|deb|rpm|apk)$/i;
const NESTED_EXT = /\.(zip|rar|7z|tar|gz|tgz|jar|apk|ipa|iso|img)$/i;

export function inspectZip(buf: Buffer): ArchiveReport {
  const empty: ArchiveReport = {
    format: "unsupported",
    entries: [],
    totalCompressed: 0,
    totalUncompressed: 0,
    zip64: false,
    truncated: false,
  };
  if (buf.length < 22) return { ...empty, reason: "too small to be a zip" };

  // EOCD sits in the last 64 KiB + 22 bytes (comment can be up to 65535 bytes).
  const searchFrom = Math.max(0, buf.length - (65535 + 22));
  let eocd = -1;
  for (let i = buf.length - 22; i >= searchFrom; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return { ...empty, reason: "no central directory" };

  let count = buf.readUInt16LE(eocd + 10);
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);
  const zip64 = count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff;
  if (zip64) {
    // ZIP64 end-of-central-directory record: locator is 20 bytes before the EOCD.
    const locator = eocd - 20;
    if (locator < 0 || buf.readUInt32LE(locator) !== 0x07064b50) {
      return { ...empty, zip64: true, reason: "zip64 without locator" };
    }
    const z64 = Number(buf.readBigUInt64LE(locator + 8));
    if (z64 + 56 > buf.length || buf.readUInt32LE(z64) !== 0x06064b50) {
      return { ...empty, zip64: true, reason: "bad zip64 record" };
    }
    count = Number(buf.readBigUInt64LE(z64 + 32));
    cdSize = Number(buf.readBigUInt64LE(z64 + 40));
    cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
  }

  if (cdOffset + cdSize > buf.length) {
    return { ...empty, zip64, reason: "central directory out of bounds" };
  }

  const entries: ArchiveEntry[] = [];
  let p = cdOffset;
  const limit = Math.min(count, 50_000);
  for (let i = 0; i < limit; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CD_SIG) break;
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const uncompressedSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const externalAttr = buf.readUInt32LE(p + 38);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    const unixMode = externalAttr >>> 16;
    const entry: ArchiveEntry = {
      name,
      compressedSize,
      uncompressedSize,
      encrypted: (flags & 0x1) !== 0,
      symlink: (unixMode & 0xf000) === 0xa000,
      method,
      localOffset: buf.readUInt32LE(p + 42),
    };
    entry.executable = EXEC_EXT.test(name);
    entry.nested = NESTED_EXT.test(name);
    entries.push(entry);
    p += 46 + nameLen + extraLen + commentLen;
  }

  const totalCompressed = entries.reduce((a, e) => a + e.compressedSize, 0);
  const totalUncompressed = entries.reduce((a, e) => a + e.uncompressedSize, 0);
  return {
    format: "zip",
    entries,
    totalCompressed,
    totalUncompressed,
    zip64,
    truncated: count > limit,
  };
}

/** Path escapes the extraction root: absolute, drive-letter, or ".." segments. */
export function isUnsafeEntryName(name: string): boolean {
  if (name.startsWith("/") || name.startsWith("\\")) return true;
  if (/^[a-zA-Z]:/.test(name)) return true;
  return name.split(/[\\/]/).some((seg) => seg === "..");
}
