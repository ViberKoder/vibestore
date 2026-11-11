import type { EngineResult, ThreatFinding } from "../types";
import { parseAsar, readAsarFile, type AsarIndex } from "../security/asar";
import { inspectZip } from "../security/archive";
import { readZipEntry } from "../security/zip-read";
import { groupByCategory, extractHosts } from "./domains";
import { runElectronHardening, runSecretsAuditor } from "./audit";

/**
 * Stage A — static auditor. Unpacks what can be read without executing anything:
 * app.asar (Electron) and the code inside ZIP packages, then runs detectors on
 * the real source instead of compressed bytes.
 */

const MAX_FILE = 8 * 1024 * 1024;
const MAX_TOTAL = 48 * 1024 * 1024;
const CODE_EXT = /\.(m?js|cjs|jsx?|tsx?|html?|json|txt|env|ya?ml|ini|cfg|config|md)$/i;

/** Electron majors older than (latest − 2) are out of support. Override with ELECTRON_LATEST_MAJOR. */
const LATEST_ELECTRON_MAJOR = Number(process.env.ELECTRON_LATEST_MAJOR ?? 40);

interface Collected {
  code: Map<string, Buffer>;
  nativeModules: string[];
  electronVersion?: string;
  sources: string[];
}

function addCode(c: Collected, name: string, data: Buffer, total: { n: number }) {
  if (data.length > MAX_FILE || total.n + data.length > MAX_TOTAL) return;
  total.n += data.length;
  c.code.set(name, data);
}

function collectFromAsar(c: Collected, buf: Buffer, idx: AsarIndex, prefix: string, total: { n: number }) {
  const label = prefix ? prefix.replace(/!\/$/, "") : "app.asar";
  c.sources.push(`${label} (${idx.files.length} files)`);
  for (const f of idx.files) {
    if (f.path.endsWith(".node")) c.nativeModules.push(`${prefix}${f.path}`);
    if (!CODE_EXT.test(f.path)) continue;
    const data = readAsarFile(buf, idx, f, MAX_FILE);
    if (data) addCode(c, `${prefix}${f.path}`, data, total);
  }
  if (!c.electronVersion) {
    const pkg = idx.files.find((f) => f.path === "package.json");
    const d = pkg && readAsarFile(buf, idx, pkg, MAX_FILE);
    const m = d?.toString("utf8").match(/"electronVersion"\s*:\s*"(\d+\.\d+\.\d+)/);
    if (m) c.electronVersion = m[1];
  }
}

function collect(buf: Buffer, fileName: string): Collected {
  const c: Collected = { code: new Map(), nativeModules: [], sources: [] };
  const total = { n: 0 };

  // Raw asar uploaded directly
  const direct = parseAsar(buf);
  if (direct && /\.asar$/i.test(fileName)) {
    collectFromAsar(c, buf, direct, "", total);
    return c;
  }

  const z = inspectZip(buf);
  if (z.format !== "zip") return c;
  for (const e of z.entries) {
    if (e.encrypted || e.symlink) continue;
    const base = e.name.split("/").pop() ?? e.name;
    if (base === "version" && !c.electronVersion) {
      const v = readZipEntry(buf, e, 64)?.toString("utf8").trim();
      if (v && /^\d+\.\d+\.\d+$/.test(v)) c.electronVersion = v;
    }
    if (e.name.endsWith(".node")) c.nativeModules.push(e.name);
    if (base.endsWith(".asar") && e.uncompressedSize <= 512 * 1024 * 1024) {
      // collectFromAsar labels the nested archive as "<entry>!/app.asar"
      const data = readZipEntry(buf, e, 512 * 1024 * 1024);
      const idx = data && parseAsar(data);
      if (data && idx) collectFromAsar(c, data, idx, `${e.name}!/`, total);
      continue;
    }
    if (CODE_EXT.test(e.name) && e.uncompressedSize <= MAX_FILE) {
      const data = readZipEntry(buf, e, MAX_FILE);
      if (data) addCode(c, e.name, data, total);
    }
  }
  if (c.sources.length === 0 && c.code.size) c.sources.push(`ZIP package (${c.code.size} code files)`);
  return c;
}

const F = (
  id: string,
  severity: ThreatFinding["severity"],
  category: ThreatFinding["category"],
  title: string,
  detail: string,
  meaning: string,
  action: string,
): ThreatFinding => ({ id, scanner: "static-audit", severity, category, title, detail, meaning, action });

export async function runStaticAuditor(buf: Buffer, fileName: string): Promise<EngineResult> {
  const started = Date.now();
  const c = collect(buf, fileName);
  if (c.code.size === 0 && c.nativeModules.length === 0) {
    return {
      scanner: "static-audit",
      displayName: "Static auditor (Stage A)",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "No packaged app code (app.asar or ZIP sources) to audit.",
      findings: [],
      meta: {},
    };
  }

  const parts: Buffer[] = [];
  for (const [name, data] of c.code) {
    parts.push(Buffer.from(`\n//--- ${name}\n`, "utf8"), data);
  }
  const code = Buffer.concat(parts);
  const findings: ThreatFinding[] = [];

  // Reuse the detectors, now on the unpacked source.
  const secrets = (await runSecretsAuditor(code, fileName)).findings;
  findings.push(...secrets.map((f) => ({ ...f, id: `sa-${f.id}` })));
  const electron = (await runElectronHardening(code, fileName)).findings;
  findings.push(...electron.map((f) => ({ ...f, id: `sa-${f.id}` })));
  // Trackers are reported by the domain categoriser below, so the privacy detector is not repeated here.

  // External hosts by category
  const groups = groupByCategory(extractHosts(code.toString("utf8")));
  if (groups.c2.length) {
    findings.push(F("sa-c2-host", "high", "trojan", `Exfiltration-style endpoints (${groups.c2.length})`,
      groups.c2.slice(0, 8).join(", "),
      "Discord webhooks, Telegram bots, paste sites and tunnels are how stealers send data out.",
      "Remove endpoints the product does not need; route real services through your own domain."));
  }
  if (groups.ads.length) {
    findings.push(F("sa-ads-hosts", "low", "adware", `Ad networks (${groups.ads.length})`,
      groups.ads.slice(0, 8).join(", "),
      "Ad SDKs track users and can serve unwanted content.",
      "Document the ad network or remove it before a mass release."));
  }
  if (groups.analytics.length) {
    findings.push(F("sa-analytics-hosts", "low", "policy", `Analytics / session replay (${groups.analytics.length})`,
      groups.analytics.slice(0, 8).join(", "),
      "Analytics and session replay record user behaviour.",
      "Disclose the analytics vendors and offer an opt-out."));
  }
  if (groups.unclassified.length > 0) {
    findings.push(F("sa-unclassified-hosts", "info", "other", `Other external hosts (${groups.unclassified.length})`,
      groups.unclassified.slice(0, 12).join(", "),
      "Hosts without a known category. Not a verdict on their own.",
      "Confirm each host belongs to the product."));
  }

  // Electron runtime age
  const major = c.electronVersion ? Number(c.electronVersion.split(".")[0]) : undefined;
  if (major !== undefined && major < LATEST_ELECTRON_MAJOR - 2) {
    findings.push(F("sa-electron-eol", "high", "vulnerability", `End-of-life Electron ${c.electronVersion}`,
      `Electron ${major} is more than two majors behind the latest known (${LATEST_ELECTRON_MAJOR}).`,
      "Out-of-support Electron versions ship unpatched Chromium and Node vulnerabilities.",
      "Upgrade to a supported Electron major and rebuild."));
  }

  // Native code outside the JS sandbox
  if (c.nativeModules.length) {
    findings.push(F("sa-native", "medium", "policy", `${c.nativeModules.length} native module(s) (.node)`,
      c.nativeModules.slice(0, 6).join(", "),
      "Native addons run compiled code with full process privileges and bypass JS-level checks.",
      "Verify each native module's source and signature; drop unused ones."));
  }

  const worst = findings.reduce(
    (a, f) => Math.max(a, ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const)[f.severity]),
    0,
  );
  const verdict: EngineResult["verdict"] =
    worst >= 4 ? "malicious" : worst >= 2 ? "suspicious" : "clean";
  const penalty = findings.reduce(
    (a, f) => a + ({ critical: 50, high: 25, medium: 10, low: 3, info: 0 } as const)[f.severity],
    0,
  );

  return {
    scanner: "static-audit",
    displayName: "Static auditor (Stage A)",
    verdict,
    score: Math.max(0, 100 - penalty),
    durationMs: Date.now() - started,
    summary: `Unpacked ${c.sources.join(", ")}; ${c.code.size} code files, ${c.nativeModules.length} native module(s); ${findings.length} finding(s).`,
    findings,
    meta: {
      sources: c.sources.join("; "),
      codeFiles: c.code.size,
      electronVersion: c.electronVersion ?? "unknown",
      nativeModules: c.nativeModules.length,
    },
  };
}
