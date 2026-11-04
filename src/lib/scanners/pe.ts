export interface PeInfo {
  isPe: boolean;
  machine?: number;
  characteristics?: number;
  sectionCount?: number;
  hasDosStub: boolean;
  importsHint: string[];
}

export function inspectPe(buf: Buffer): PeInfo {
  const info: PeInfo = { isPe: false, hasDosStub: false, importsHint: [] };

  if (buf.length < 64) return info;
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return info; // MZ

  info.hasDosStub = true;
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 >= buf.length) return info;
  if (buf.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") return info;

  info.isPe = true;
  info.machine = buf.readUInt16LE(peOffset + 4);
  info.sectionCount = buf.readUInt16LE(peOffset + 6);
  info.characteristics = buf.readUInt16LE(peOffset + 22);

  const ascii = buf.toString("latin1");
  const libs = [
    "kernel32.dll",
    "user32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "urlmon.dll",
    "ntdll.dll",
    "crypt32.dll",
  ];
  for (const lib of libs) {
    if (ascii.toLowerCase().includes(lib)) info.importsHint.push(lib);
  }

  return info;
}
