import path from "path";
import type { EngineResult, ThreatFinding } from "../types";
import { sampleEntropy } from "./entropy";
import { inspectPe } from "./pe";
import { STEALER_PATTERNS, SUSPICIOUS_EXTS } from "./signatures";

export async function runVibeGuard(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const text = buf.toString("latin1");
  const findings: ThreatFinding[] = [];

  for (const sig of STEALER_PATTERNS) {
    if (sig.pattern.test(text)) {
      findings.push({
        id: `vg-${sig.id}`,
        scanner: "vibeguard",
        severity: sig.severity,
        title: sig.title,
        detail: "VibeGuard proprietary YARA-like rule matched.",
        category: sig.id.includes("wallet") || sig.id.includes("cookie")
          ? "stealer"
          : sig.id.includes("keylog")
            ? "trojan"
            : "stealer",
      });
    }
  }

  const ext = path.extname(fileName).toLowerCase();
  if (SUSPICIOUS_EXTS.includes(ext) && buf.length > 0) {
    findings.push({
      id: "vg-risky-ext",
      scanner: "vibeguard",
      severity: "medium",
      title: `Risky script extension ${ext}`,
      detail: "Scriptable formats need extra review before mass release.",
      category: "policy",
    });
  }

  // Obfuscation: long base64 blobs
  const b64 = text.match(/[A-Za-z0-9+/]{200,}={0,2}/g);
  if (b64 && b64.length >= 3) {
    findings.push({
      id: "vg-b64",
      scanner: "vibeguard",
      severity: "medium",
      title: "Heavy Base64 payload blobs",
      detail: `Found ${b64.length} large encoded blobs — common in packers/stealers.`,
      category: "packed",
    });
  }

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const score = Math.max(0, 100 - critical * 35 - high * 18 - findings.length * 5);
  const verdict =
    critical > 0 ? "malicious" : findings.length > 0 ? "suspicious" : "clean";

  return {
    scanner: "vibeguard",
    displayName: "VibeGuard",
    verdict,
    score,
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? "Proprietary stealer/trojan rules: clean."
        : `VibeGuard raised ${findings.length} proprietary finding(s).`,
    findings,
    meta: { ruleset: "vibeguard-2026.10" },
  };
}

export async function runEntropyScanner(buf: Buffer): Promise<EngineResult> {
  const started = Date.now();
  const entropy = sampleEntropy(buf);
  const findings: ThreatFinding[] = [];

  if (entropy >= 7.6 && buf.length > 4096) {
    findings.push({
      id: "ent-high",
      scanner: "entropy",
      severity: "medium",
      title: "High entropy (likely packed/encrypted)",
      detail: `Shannon entropy ${entropy.toFixed(2)}/8. Packed malware often hides here.`,
      category: "packed",
    });
  } else if (entropy >= 7.2 && buf.length > 4096) {
    findings.push({
      id: "ent-elevated",
      scanner: "entropy",
      severity: "low",
      title: "Elevated entropy",
      detail: `Entropy ${entropy.toFixed(2)} — compressed assets or mild packing.`,
      category: "packed",
    });
  }

  return {
    scanner: "entropy",
    displayName: "Entropy Analyzer",
    verdict: findings.some((f) => f.severity !== "low")
      ? "suspicious"
      : findings.length
        ? "suspicious"
        : "clean",
    score: findings.length ? (entropy >= 7.6 ? 55 : 78) : 97,
    durationMs: Date.now() - started,
    summary: `Entropy ${entropy.toFixed(2)} bits/byte.`,
    findings,
    meta: { entropy: Number(entropy.toFixed(3)) },
  };
}

export async function runPeInspector(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const pe = inspectPe(buf);
  const findings: ThreatFinding[] = [];
  const looksExe = /\.(exe|dll|sys|scr)$/i.test(fileName);

  if (looksExe && !pe.isPe) {
    findings.push({
      id: "pe-fake",
      scanner: "pe-inspector",
      severity: "high",
      title: "Executable extension without PE header",
      detail: "File claims to be Windows binary but lacks valid PE structure.",
      category: "trojan",
    });
  }

  if (pe.isPe) {
    if ((pe.sectionCount ?? 0) > 12) {
      findings.push({
        id: "pe-sections",
        scanner: "pe-inspector",
        severity: "low",
        title: "Unusual PE section count",
        detail: `${pe.sectionCount} sections — packers sometimes inflate this.`,
        category: "packed",
      });
    }
    const risky = pe.importsHint.filter((x) =>
      ["wininet.dll", "urlmon.dll", "ws2_32.dll"].includes(x),
    );
    if (risky.length >= 2 && pe.importsHint.includes("advapi32.dll")) {
      findings.push({
        id: "pe-net-cred",
        scanner: "pe-inspector",
        severity: "medium",
        title: "Network + credential API mix",
        detail: `Imports: ${pe.importsHint.join(", ")}`,
        category: "network",
      });
    }
  }

  if (!looksExe && !pe.isPe) {
    return {
      scanner: "pe-inspector",
      displayName: "PE Inspector",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "Not a Windows PE target — skipped.",
      findings: [],
      meta: { skipped: true },
    };
  }

  const score = Math.max(0, 100 - findings.length * 18);
  return {
    scanner: "pe-inspector",
    displayName: "PE Inspector",
    verdict: findings.some((f) => f.severity === "high" || f.severity === "critical")
      ? "malicious"
      : findings.length
        ? "suspicious"
        : "clean",
    score,
    durationMs: Date.now() - started,
    summary: pe.isPe
      ? `Valid PE · ${pe.sectionCount ?? "?"} sections · imports probed.`
      : "PE structure anomalies detected.",
    findings,
    meta: {
      isPe: pe.isPe,
      sections: pe.sectionCount ?? 0,
      imports: pe.importsHint.join(",") || "none",
    },
  };
}

export async function runNetworkSink(buf: Buffer): Promise<EngineResult> {
  const started = Date.now();
  const text = buf.toString("utf8", 0, Math.min(buf.length, 1_500_000));
  const findings: ThreatFinding[] = [];

  const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  const unique = [...new Set(urls)].slice(0, 40);
  const shady = unique.filter((u) =>
    /ngrok|trycloudflare|pastebin|raw\.githubusercontent|discord\.com\/api|telegram\.org|onion\b|bit\.ly|tinyurl/i.test(
      u,
    ),
  );

  for (const u of shady.slice(0, 8)) {
    findings.push({
      id: `net-${Buffer.from(u).toString("base64").slice(0, 10)}`,
      scanner: "network-sink",
      severity: /discord|telegram|onion/i.test(u) ? "high" : "medium",
      title: "Suspicious outbound sink",
      detail: u.slice(0, 180),
      category: "network",
    });
  }

  if (unique.length > 25) {
    findings.push({
      id: "net-many-urls",
      scanner: "network-sink",
      severity: "low",
      title: "Many embedded URLs",
      detail: `${unique.length} unique URLs embedded — review for unexpected C2.`,
      category: "network",
    });
  }

  return {
    scanner: "network-sink",
    displayName: "Network Sink Scanner",
    verdict: findings.some((f) => f.severity === "high" || f.severity === "critical")
      ? "suspicious"
      : findings.length
        ? "suspicious"
        : "clean",
    score: Math.max(0, 100 - findings.length * 12),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? `No shady sinks in ${unique.length} URL(s).`
        : `Flagged ${findings.length} network indicator(s).`,
    findings,
    meta: { urlCount: unique.length, shadyCount: shady.length },
  };
}

export async function runWebStatic(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const ext = path.extname(fileName).toLowerCase();
  const webExts = [".html", ".htm", ".js", ".jsx", ".tsx", ".vue", ".css", ".zip"];
  if (!webExts.includes(ext) && !buf.toString("utf8", 0, 200).includes("<html")) {
    return {
      scanner: "web-static",
      displayName: "Web Static Auditor",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "Not a web artifact — skipped.",
      findings: [],
      meta: { skipped: true },
    };
  }

  const text = buf.toString("utf8", 0, Math.min(buf.length, 2_000_000));
  const findings: ThreatFinding[] = [];

  if (/document\.cookie/i.test(text) && /fetch\s*\(|XMLHttpRequest/i.test(text)) {
    findings.push({
      id: "web-cookie-exfil",
      scanner: "web-static",
      severity: "high",
      title: "Possible cookie exfiltration",
      detail: "Reads document.cookie and performs network request.",
      category: "vulnerability",
    });
  }
  if (/eval\s*\(|new Function\s*\(/i.test(text)) {
    findings.push({
      id: "web-eval",
      scanner: "web-static",
      severity: "medium",
      title: "Dynamic code execution",
      detail: "eval/new Function increases XSS and supply-chain risk.",
      category: "bug",
    });
  }
  if (/innerHTML\s*=/i.test(text) && /location\.|document\.URL|hash/i.test(text)) {
    findings.push({
      id: "web-domxss",
      scanner: "web-static",
      severity: "high",
      title: "Potential DOM XSS sink",
      detail: "innerHTML assigned from URL-derived data.",
      category: "vulnerability",
    });
  }
  if (/<script[^>]+src=["']https?:\/\/[^"']+/i.test(text)) {
    const third = text.match(/<script[^>]+src=["'](https?:\/\/[^"']+)/gi) ?? [];
    if (third.length > 0) {
      findings.push({
        id: "web-third-party",
        scanner: "web-static",
        severity: "low",
        title: "Third-party scripts",
        detail: `${third.length} remote script tag(s) — pin & SRI recommended.`,
        category: "policy",
      });
    }
  }

  return {
    scanner: "web-static",
    displayName: "Web Static Auditor",
    verdict: findings.some((f) => f.severity === "high" || f.severity === "critical")
      ? "suspicious"
      : findings.length
        ? "suspicious"
        : "clean",
    score: Math.max(0, 100 - findings.length * 14),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? "No common web vuln/bug patterns."
        : `Web auditor found ${findings.length} issue(s).`,
    findings,
  };
}
