/**
 * Android binary XML (AndroidManifest.xml inside an APK) reader.
 * Only start/end elements and attributes are decoded; that is all the
 * manifest checks need. Format per AOSP ResXMLTree (types 0x0001, 0x0102, 0x0103).
 */

export interface AxmlValue {
  str?: string;
  num?: number;
  bool?: boolean;
}

export interface AxmlElement {
  tag: string;
  attrs: Record<string, AxmlValue>;
  depth: number;
}

const TYPE_STRING_POOL = 0x0001;
const TYPE_START_ELEMENT = 0x0102;
const TYPE_END_ELEMENT = 0x0103;
const FLAG_UTF8 = 1 << 8;
const TYPE_REFERENCE = 0x01;
const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

function readStringPool(buf: Buffer, off: number): string[] {
  const count = buf.readUInt32LE(off + 8);
  const flags = buf.readUInt32LE(off + 16);
  const headerSize = buf.readUInt16LE(off + 2);
  const stringsStart = buf.readUInt32LE(off + 20);
  const utf8 = (flags & FLAG_UTF8) !== 0;
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const at = off + stringsStart + buf.readUInt32LE(off + headerSize + i * 4);
    if (utf8) {
      let p = at;
      let charLen = buf[p++];
      if (charLen & 0x80) charLen = ((charLen & 0x7f) << 8) | buf[p++];
      let byteLen = buf[p++];
      if (byteLen & 0x80) byteLen = ((byteLen & 0x7f) << 8) | buf[p++];
      out.push(buf.subarray(p, p + byteLen).toString("utf8"));
    } else {
      let len = buf.readUInt16LE(at);
      let p = at + 2;
      if (len & 0x8000) {
        len = ((len & 0x7fff) << 16) | buf.readUInt16LE(p);
        p += 2;
      }
      out.push(buf.subarray(p, p + len * 2).toString("utf16le"));
    }
  }
  return out;
}

export function parseAxml(buf: Buffer, maxElements = 20_000): AxmlElement[] | null {
  if (buf.length < 8 || buf.readUInt16LE(0) !== 0x0003) return null;
  const elements: AxmlElement[] = [];
  let strings: string[] = [];
  let off = buf.readUInt16LE(2);
  let depth = 0;
  while (off + 8 <= buf.length && elements.length < maxElements) {
    const type = buf.readUInt16LE(off);
    const size = buf.readUInt32LE(off + 4);
    if (size < 8 || off + size > buf.length) break;
    if (type === TYPE_STRING_POOL) {
      strings = readStringPool(buf, off);
    } else if (type === TYPE_START_ELEMENT) {
      const name = strings[buf.readUInt32LE(off + 20)] ?? "";
      const attrStart = buf.readUInt16LE(off + 24);
      const attrSize = buf.readUInt16LE(off + 26) || 20;
      const attrCount = buf.readUInt16LE(off + 28);
      const attrs: Record<string, AxmlValue> = {};
      for (let i = 0; i < attrCount; i++) {
        const a = off + 16 + attrStart + i * attrSize;
        if (a + 20 > buf.length) break;
        const attrName = strings[buf.readUInt32LE(a + 4)] ?? "";
        const raw = buf.readUInt32LE(a + 8);
        const dataType = buf[a + 15];
        const data = buf.readUInt32LE(a + 16);
        const value: AxmlValue = {};
        if (raw !== 0xffffffff) value.str = strings[raw];
        if (dataType === TYPE_STRING) value.str = strings[data];
        else if (dataType === TYPE_INT_DEC) value.num = buf.readInt32LE(a + 16);
        else if (dataType === TYPE_INT_HEX) value.num = data;
        else if (dataType === TYPE_INT_BOOLEAN) value.bool = data !== 0;
        else if (dataType === TYPE_REFERENCE && value.str === undefined) value.str = `@0x${data.toString(16)}`;
        attrs[attrName] = value;
      }
      elements.push({ tag: name, attrs, depth });
      depth++;
    } else if (type === TYPE_END_ELEMENT) {
      depth = Math.max(0, depth - 1);
    }
    off += size;
  }
  return elements;
}

/** Int, bool or numeric-string value of an attribute. */
export function intAttr(v: AxmlValue | undefined): number | undefined {
  if (!v) return undefined;
  if (v.num !== undefined) return v.num;
  if (v.str !== undefined && /^\d+$/.test(v.str)) return Number(v.str);
  return undefined;
}

export function boolAttr(v: AxmlValue | undefined): boolean | undefined {
  if (!v) return undefined;
  if (v.bool !== undefined) return v.bool;
  if (v.str === "true") return true;
  if (v.str === "false") return false;
  if (v.num !== undefined) return v.num !== 0;
  return undefined;
}
