import type { EngineResult, ThreatFinding } from "../types";
import { inspectZip } from "../security/archive";
import { parseAsar, readAsarFile } from "../security/asar";
import { readZipEntry } from "../security/zip-read";

/**
 * Dependency advisories. Packages are read from what ships with the build
 * (package-lock.json, node_modules/*\/package.json inside app.asar or a ZIP) and
 * matched against the OSV database (https://osv.dev). Lookup failures are
 * reported as unavailable, never as "no vulnerabilities".
 */

export const OSV_API_BASE = (process.env.OSV_API_BASE ?? "https://api.osv.dev").replace(/\/$/, "");

export interface NpmPackage {
  name: string;
  version: string;
}

const MAX_PACKAGES = 2000;
const MAX_JSON = 2 * 1024 * 1024;

function nameFromPath(p: string): string | null {
  const idx = p.lastIndexOf("node_modules/");
  if (idx < 0) return null;
  const rest = p.slice(idx + "node_modules/".length).split("/");
  if (rest[0].startsWith("@") && rest.length > 1) return `${rest[0]}/${rest[1]}`;
  return rest[0] || null;
}

/** npm lockfile v1 (dependencies) and v2/v3 (packages). */
export function packagesFromLock(json: string): NpmPackage[] {
  let lock: { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string }> };
  try {
    lock = JSON.parse(json);
  } catch {
    return [];
  }
  const out: NpmPackage[] = [];
  if (lock.packages) {
    for (const [path, info] of Object.entries(lock.packages)) {
      const name = path === "" ? null : nameFromPath(path);
      if (name && info.version) out.push({ name, version: info.version });
    }
  } else if (lock.dependencies) {
    for (const [name, info] of Object.entries(lock.dependencies)) {
      if (info.version) out.push({ name, version: info.version });
    }
  }
  return out;
}

function packageFromManifest(json: string): NpmPackage | null {
  try {
    const m = JSON.parse(json) as { name?: unknown; version?: unknown };
    if (typeof m.name === "string" && typeof m.version === "string" && m.version.length < 64) {
      return { name: m.name, version: m.version };
    }
  } catch {
    /* not a manifest */
  }
  return null;
}

export function collectNpmPackages(buf: Buffer, fileName: string): { packages: NpmPackage[]; sources: string[] } {
  const found = new Map<string, NpmPackage>();
  const sources: string[] = [];
  const add = (p: NpmPackage | null) => {
    if (p && found.size < MAX_PACKAGES) found.set(`${p.name}@${p.version}`, p);
  };
  const fromAsar = (data: Buffer, label: string) => {
    const idx = parseAsar(data);
    if (!idx) return;
    let n = 0;
    for (const f of idx.files) {
      if (!/(^|\/)node_modules\/.+\/package\.json$/.test(f.path) && f.path !== "package.json") continue;
      const body = readAsarFile(data, idx, f, MAX_JSON);
      if (!body) continue;
      if (f.path === "package.json") continue; // the app's own manifest, not shipped dependencies
      add(packageFromManifest(body.toString("utf8")));
      n++;
    }
    sources.push(`${label} (${n} shipped packages)`);
  };

  if (/\.asar$/i.test(fileName) && parseAsar(buf)) {
    fromAsar(buf, "app.asar");
    return { packages: [...found.values()], sources };
  }

  const z = inspectZip(buf);
  if (z.format !== "zip") return { packages: [], sources };
  for (const e of z.entries) {
    if (e.encrypted || e.symlink) continue;
    if (/(^|\/)package-lock\.json$/.test(e.name) && e.uncompressedSize <= MAX_JSON) {
      const data = readZipEntry(buf, e, MAX_JSON);
      if (data) {
        const pk = packagesFromLock(data.toString("utf8"));
        pk.forEach(add);
        sources.push(`${e.name} (${pk.length} locked packages)`);
      }
    } else if (/\.asar$/i.test(e.name) && e.uncompressedSize <= 512 * 1024 * 1024) {
      const data = readZipEntry(buf, e, 512 * 1024 * 1024);
      if (data) fromAsar(data, `${e.name}!/app.asar`);
    } else if (/(^|\/)node_modules\/.+\/package\.json$/.test(e.name) && e.uncompressedSize <= MAX_JSON) {
      const data = readZipEntry(buf, e, MAX_JSON);
      if (data) add(packageFromManifest(data.toString("utf8")));
    }
  }
  return { packages: [...found.values()], sources };
}

interface OsvVuln {
  id: string;
  summary?: string;
  database_specific?: { severity?: string };
  aliases?: string[];
}

function mapSeverity(v: OsvVuln): ThreatFinding["severity"] {
  const s = (v.database_specific?.severity ?? "").toUpperCase();
  if (s === "CRITICAL") return "critical";
  if (s === "HIGH") return "high";
  if (s === "MODERATE" || s === "MEDIUM") return "medium";
  if (s === "LOW") return "low";
  return "medium";
}

async function osvQueryBatch(pkgs: NpmPackage[]): Promise<string[][]> {
  const results: string[][] = [];
  for (let i = 0; i < pkgs.length; i += 500) {
    const chunk = pkgs.slice(i, i + 500);
    const res = await fetch(`${OSV_API_BASE}/v1/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: chunk.map((p) => ({ version: p.version, package: { name: p.name, ecosystem: "npm" } })),
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
    if (!res.ok) throw new Error(`OSV responded ${res.status}`);
    const json = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
    for (const r of json.results ?? []) results.push((r.vulns ?? []).map((v) => v.id));
  }
  return results;
}

async function osvVuln(id: string): Promise<OsvVuln | null> {
  const res = await fetch(`${OSV_API_BASE}/v1/vulns/${encodeURIComponent(id)}`, {
    cache: "no-store",
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) return null;
  return (await res.json()) as OsvVuln;
}

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

export async function runDependencyEngine(buf: Buffer, fileName: string): Promise<EngineResult> {
  const started = Date.now();
  const { packages, sources } = collectNpmPackages(buf, fileName);
  if (packages.length === 0) {
    return {
      scanner: "dependencies",
      displayName: "Dependency advisories (OSV)",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "No npm packages found in the build (no package-lock.json or shipped node_modules).",
      findings: [],
      meta: { ecosystem: "npm" },
    };
  }

  let perQuery: string[][];
  try {
    perQuery = await osvQueryBatch(packages);
  } catch (err) {
    return {
      scanner: "dependencies",
      displayName: "Dependency advisories (OSV)",
      verdict: "error",
      score: 0,
      durationMs: Date.now() - started,
      summary: `OSV lookup unavailable: ${err instanceof Error ? err.message : String(err)}. Dependencies were NOT checked.`,
      findings: [],
      meta: { packages: packages.length, sources: sources.join("; ") },
    };
  }

  // Fetch details once per unique advisory, bounded.
  const ids = [...new Set(perQuery.flat())];
  const details = new Map<string, OsvVuln>();
  for (const id of ids.slice(0, 60)) {
    try {
      const v = await osvVuln(id);
      if (v) details.set(id, v);
    } catch {
      /* keep the bare id */
    }
  }

  const findings: ThreatFinding[] = [];
  packages.forEach((p, i) => {
    const vulns = perQuery[i] ?? [];
    if (!vulns.length) return;
    let worst: ThreatFinding["severity"] = "low";
    for (const id of vulns) {
      const d = details.get(id);
      const sev = d ? mapSeverity(d) : "medium";
      if (SEV_RANK[sev] > SEV_RANK[worst]) worst = sev;
    }
    // A vulnerable library is not malware: cap at "high" so it means "fix before release", not "blocked".
    if (worst === "critical") worst = "high";
    const names = vulns.slice(0, 6).map((id) => details.get(id)?.summary?.slice(0, 80) ?? id);
    findings.push({
      id: `dep-${p.name}-${p.version}`,
      scanner: "dependencies",
      severity: worst,
      category: "vulnerability",
      title: `${p.name}@${p.version}: ${vulns.length} known advisor${vulns.length === 1 ? "y" : "ies"}`,
      detail: `${vulns.slice(0, 8).join(", ")} — ${names.join("; ")}`,
      meaning: "A library shipped in this build has publicly known vulnerabilities.",
      action: "Upgrade the package to a fixed version and rebuild.",
    });
  });
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);

  return {
    scanner: "dependencies",
    displayName: "Dependency advisories (OSV)",
    // Advisories are vulnerabilities, not malicious code, so the verdict never says "malicious".
    verdict: findings.length ? "suspicious" : "clean",
    score: Math.max(0, 100 - findings.reduce((a, f) => a + ({ critical: 40, high: 20, medium: 8, low: 2, info: 0 } as const)[f.severity], 0)),
    durationMs: Date.now() - started,
    summary: findings.length
      ? `${packages.length} packages checked against OSV: ${findings.length} with known advisories.`
      : `${packages.length} packages checked against OSV: no known advisories.`,
    findings: findings.slice(0, 40),
    meta: { packages: packages.length, advisories: ids.length, sources: sources.join("; ") },
  };
}
