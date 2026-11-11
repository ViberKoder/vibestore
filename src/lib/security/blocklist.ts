import { promises as fs } from "fs";
import path from "path";
import { DATA_DIR } from "../paths";

/**
 * Known-bad build hashes (SHA-256). Sources:
 *  - env BLOCKLIST_SHA256 — comma or whitespace separated
 *  - file <DATA_DIR>/blocklist.txt — one hash per line, "#" starts a comment
 * Matching builds are blocked regardless of what the engines say.
 */
const SHA256 = /^[a-f0-9]{64}$/;

let cache: { hashes: Set<string>; loadedAt: number } | null = null;
const TTL_MS = 30_000;

function parseList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((l) => l.split("#")[0].trim().toLowerCase())
    .filter((l) => SHA256.test(l));
}

export async function loadBlocklist(): Promise<Set<string>> {
  if (cache && Date.now() - cache.loadedAt < TTL_MS) return cache.hashes;
  const hashes = new Set<string>(parseList(process.env.BLOCKLIST_SHA256 ?? ""));
  try {
    for (const h of parseList(await fs.readFile(path.join(DATA_DIR, "blocklist.txt"), "utf8"))) {
      hashes.add(h);
    }
  } catch {
    /* optional file */
  }
  cache = { hashes, loadedAt: Date.now() };
  return hashes;
}

export async function isBlocked(sha256: string): Promise<boolean> {
  return (await loadBlocklist()).has(sha256.toLowerCase());
}

export function blocklistSize(): number {
  return cache?.hashes.size ?? 0;
}

