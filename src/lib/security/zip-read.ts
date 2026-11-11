import zlib from "zlib";
import type { ArchiveEntry } from "./archive";

/**
 * Read one entry's bytes from a ZIP, with a hard output cap so a bomb cannot
 * exhaust memory. Supports stored (0) and deflate (8); anything else returns null.
 */
export function readZipEntry(buf: Buffer, entry: ArchiveEntry, maxBytes: number): Buffer | null {
  const p = entry.localOffset;
  if (p + 30 > buf.length || buf.readUInt32LE(p) !== 0x04034b50) return null;
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const start = p + 30 + nameLen + extraLen;
  const end = start + entry.compressedSize;
  if (end > buf.length) return null;
  const data = buf.subarray(start, end);
  try {
    if (entry.method === 0) return data.length > maxBytes ? null : Buffer.from(data);
    if (entry.method === 8) {
      return zlib.inflateRawSync(data, { maxOutputLength: maxBytes });
    }
  } catch {
    return null;
  }
  return null;
}
