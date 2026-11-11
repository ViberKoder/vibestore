/**
 * Electron app.asar reader (header only + per-file reads). Format:
 *   [0..3]  pickle payload size (4)
 *   [4..7]  header pickle size H
 *   [8..]   header pickle: payload size, string length L, then JSON (L bytes at offset 16)
 *   file data starts at 8 + H; each file's "offset" is relative to that base.
 */
export interface AsarFile {
  path: string;
  size: number;
  offset: number;
  unpacked: boolean;
}

export interface AsarIndex {
  files: AsarFile[];
  base: number;
  header: unknown;
}

export function parseAsar(buf: Buffer, maxHeader = 16 * 1024 * 1024): AsarIndex | null {
  if (buf.length < 16 || buf.readUInt32LE(0) !== 4) return null;
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  if (headerSize > maxHeader || jsonLen > headerSize || 16 + jsonLen > buf.length) return null;
  let header: unknown;
  try {
    header = JSON.parse(buf.subarray(16, 16 + jsonLen).toString("utf8"));
  } catch {
    return null;
  }
  const files: AsarFile[] = [];
  const walk = (node: unknown, prefix: string) => {
    if (!node || typeof node !== "object") return;
    const dir = (node as { files?: Record<string, unknown> }).files;
    if (!dir) return;
    for (const [name, child] of Object.entries(dir)) {
      const c = child as { size?: number; offset?: string; unpacked?: boolean; files?: unknown };
      const path = prefix ? `${prefix}/${name}` : name;
      if (c.files) walk(c, path);
      else if (typeof c.size === "number") {
        files.push({
          path,
          size: c.size,
          offset: Number(c.offset ?? 0),
          unpacked: Boolean(c.unpacked),
        });
      }
    }
  };
  walk(header, "");
  return { files, base: 8 + headerSize, header };
}

/** Read a packed (non-unpacked) file's bytes from the archive. */
export function readAsarFile(buf: Buffer, index: AsarIndex, file: AsarFile, maxBytes: number): Buffer | null {
  if (file.unpacked || file.size > maxBytes) return null;
  const start = index.base + file.offset;
  const end = start + file.size;
  if (end > buf.length) return null;
  return buf.subarray(start, end);
}
