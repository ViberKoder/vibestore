/**
 * Content sniffing by magic bytes. The declared extension is attacker-controlled,
 * so the real format decides which checks apply and whether an extension lies.
 */
export type SniffedType =
  | "pe"
  | "elf"
  | "macho"
  | "zip"
  | "ole"
  | "7z"
  | "rar"
  | "pdf"
  | "html"
  | "script"
  | "wasm"
  | "unknown";

export function sniffType(buf: Buffer): SniffedType {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    // MZ header: confirm the PE signature at e_lfanew to avoid plain "MZ" text.
    if (buf.length >= 0x40) {
      const peOffset = buf.readUInt32LE(0x3c);
      if (peOffset + 4 <= buf.length && buf.readUInt32LE(peOffset) === 0x00004550) {
        return "pe";
      }
    }
    return "unknown";
  }
  if (buf.length >= 4 && buf.readUInt32BE(0) === 0x7f454c46) return "elf";
  if (buf.length >= 4) {
    const m = buf.readUInt32BE(0);
    if (m === 0xfeedface || m === 0xfeedfacf || m === 0xcefaedfe || m === 0xcffaedfe || m === 0xcafebabe) {
      return "macho";
    }
  }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05)) {
    return "zip";
  }
  if (buf.length >= 8 && buf.readUInt32BE(0) === 0xd0cf11e0 && buf.readUInt32BE(4) === 0xa1b11ae1) {
    return "ole";
  }
  if (buf.length >= 6 && buf.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]))) {
    return "7z";
  }
  if (buf.length >= 4 && buf.subarray(0, 4).toString("latin1") === "Rar!") return "rar";
  if (buf.length >= 4 && buf.subarray(0, 4).toString("latin1") === "%PDF") return "pdf";
  if (buf.length >= 4 && buf.subarray(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d]))) return "wasm";
  const head = buf.subarray(0, 512).toString("utf8").trimStart().toLowerCase();
  if (head.startsWith("<!doctype html") || head.startsWith("<html")) return "html";
  if (head.startsWith("#!") ) return "script";
  return "unknown";
}

export const EXECUTABLE_TYPES: SniffedType[] = ["pe", "elf", "macho", "script", "wasm"];

/** What each declared extension is expected to contain. */
const EXPECTED: Record<string, SniffedType[]> = {
  ".exe": ["pe"],
  ".dll": ["pe"],
  ".scr": ["pe"],
  ".com": ["pe"],
  ".sys": ["pe"],
  ".msi": ["ole"],
  ".zip": ["zip"],
  ".jar": ["zip"],
  ".apk": ["zip"],
  ".ipa": ["zip"],
  ".appimage": ["elf"],
  ".7z": ["7z"],
  ".rar": ["rar"],
  ".html": ["html", "unknown"],
  ".htm": ["html", "unknown"],
  ".wasm": ["wasm"],
  ".pdf": ["pdf"],
};

export interface TypeVerdict {
  sniffed: SniffedType;
  /** Extension says one thing, bytes say another. */
  mismatch: boolean;
  /** Executable bytes behind a non-executable extension (e.g. photo.jpg). */
  disguisedExecutable: boolean;
}

export function judgeType(fileName: string, buf: Buffer): TypeVerdict {
  const sniffed = sniffType(buf);
  const ext = fileName.includes(".") ? "." + fileName.split(".").pop()!.toLowerCase() : "";
  const expected = EXPECTED[ext];
  const isExecutable = EXECUTABLE_TYPES.includes(sniffed);
  const claimsExecutable = ext === ".exe" || ext === ".dll" || ext === ".scr" || ext === ".com" || ext === ".sys";
  // Extensions whose content is legitimately a script or binary blob.
  const scriptable = new Set([".sh", ".py", ".js", ".bat", ".ps1", ".html", ".htm", ".appimage", ".wasm", ".bin"]);
  return {
    sniffed,
    mismatch: Boolean(expected && !expected.includes(sniffed)),
    disguisedExecutable: isExecutable && !claimsExecutable && ext !== "" && !scriptable.has(ext),
  };
}
