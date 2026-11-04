/**
 * Efficient text extraction from large binaries (installers up to hundreds of MB).
 * Samples head / mid / tail so we don't load multi‑hundred‑MB strings into RAM twice.
 */
export function extractSearchText(buf: Buffer, budget = 3_000_000): string {
  if (buf.length <= budget) {
    return buf.toString("latin1");
  }
  const chunk = Math.floor(budget / 3);
  const midStart = Math.max(0, Math.floor(buf.length / 2) - Math.floor(chunk / 2));
  const tailStart = Math.max(0, buf.length - chunk);
  return Buffer.concat([
    buf.subarray(0, chunk),
    buf.subarray(midStart, midStart + chunk),
    buf.subarray(tailStart),
  ]).toString("latin1");
}

export function collectAsciiStrings(
  buf: Buffer,
  opts?: { minLen?: number; maxStrings?: number; budget?: number },
): string[] {
  const minLen = opts?.minLen ?? 6;
  const maxStrings = opts?.maxStrings ?? 4000;
  const text = extractSearchText(buf, opts?.budget ?? 4_000_000);
  const re = new RegExp(`[\\x20-\\x7e]{${minLen},}`, "g");
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(re)) {
    const s = m[0];
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= maxStrings) break;
  }
  return out;
}

export function looksLikeElectron(text: string): boolean {
  return (
    /Electron|electron\.asar|app\.asar|ELECTRON_RUN_AS_NODE|chrome_100_percent\.pak/i.test(
      text,
    )
  );
}
