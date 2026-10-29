import { createHash } from "crypto";
import type { EngineResult, ThreatFinding } from "../types";
import { STEALER_PATTERNS, VIRUS_NAME_HINTS } from "./signatures";

interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

async function queryVirusTotal(
  sha256: string,
): Promise<{ stats: VtStats; names: string[] } | null> {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return null;

  try {
    const res = await fetch(
      `https://www.virustotal.com/api/v3/files/${sha256}`,
      {
        headers: { "x-apikey": key },
        cache: "no-store",
      },
    );
    if (res.status === 404) {
      return {
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 70 },
        names: [],
      };
    }
    if (!res.ok) return null;
    const json = (await res.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: VtStats;
          popular_threat_classification?: {
            popular_threat_name?: Array<{ value: string }>;
          };
        };
      };
    };
    const stats = json.data?.attributes?.last_analysis_stats;
    if (!stats) return null;
    const names =
      json.data?.attributes?.popular_threat_classification?.popular_threat_name?.map(
        (n) => n.value,
      ) ?? [];
    return { stats, names };
  } catch {
    return null;
  }
}

function emulateVirusTotal(buf: Buffer, fileName: string): VtStats & {
  names: string[];
  findings: ThreatFinding[];
} {
  const text = buf.toString("latin1");
  const findings: ThreatFinding[] = [];
  let malicious = 0;
  let suspicious = 0;
  const names: string[] = [];

  for (const sig of STEALER_PATTERNS) {
    if (sig.pattern.test(text)) {
      malicious += sig.severity === "critical" ? 12 : 6;
      suspicious += 3;
      names.push(sig.id);
      findings.push({
        id: `vt-${sig.id}`,
        scanner: "virustotal",
        severity: sig.severity,
        title: `Multi-engine consensus: ${sig.title}`,
        detail: "Emulated VirusTotal vendor cluster flagged this indicator.",
        category: "stealer",
      });
    }
  }

  for (const hint of VIRUS_NAME_HINTS) {
    if (text.toLowerCase().includes(hint) && text.toLowerCase().includes("payload")) {
      malicious += 8;
      names.push(`generic.${hint}`);
    }
  }

  if (/X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/.test(text)) {
    malicious = 60;
    names.push("eicar");
    findings.push({
      id: "vt-eicar",
      scanner: "virustotal",
      severity: "critical",
      title: "EICAR detected across vendors",
      detail: "Classic antivirus test file.",
      category: "virus",
    });
  }

  // Slight suspicion for double extensions
  if (/\.(pdf|jpg|png|txt)\.exe$/i.test(fileName)) {
    suspicious += 15;
    findings.push({
      id: "vt-double-ext",
      scanner: "virustotal",
      severity: "high",
      title: "Double extension disguise",
      detail: `Filename ${fileName} looks like a document but is an executable.`,
      category: "trojan",
    });
  }

  const harmless = Math.max(0, 70 - malicious - suspicious);
  return {
    malicious: Math.min(malicious, 70),
    suspicious: Math.min(suspicious, 20),
    harmless,
    undetected: Math.max(0, 70 - malicious - suspicious - harmless),
    names,
    findings,
  };
}

export async function runVirusTotal(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const sha256 = createHash("sha256").update(buf).digest("hex");
  const live = await queryVirusTotal(sha256);

  if (live) {
    const { stats, names } = live;
    const findings: ThreatFinding[] = [];
    if (stats.malicious > 0) {
      findings.push({
        id: "vt-malicious",
        scanner: "virustotal",
        severity: stats.malicious >= 5 ? "critical" : "high",
        title: `${stats.malicious} VirusTotal engines flagged malware`,
        detail: names.length
          ? `Popular names: ${names.slice(0, 5).join(", ")}`
          : "See VirusTotal for vendor breakdown.",
        category: "virus",
      });
    } else if (stats.suspicious > 2) {
      findings.push({
        id: "vt-suspicious",
        scanner: "virustotal",
        severity: "medium",
        title: `${stats.suspicious} engines marked suspicious`,
        detail: "Not confirmed malware, but vendors disagree.",
        category: "other",
      });
    }

    const score = Math.max(
      0,
      100 - stats.malicious * 8 - stats.suspicious * 3,
    );
    const verdict =
      stats.malicious >= 3
        ? "malicious"
        : stats.malicious > 0 || stats.suspicious > 2
          ? "suspicious"
          : "clean";

    return {
      scanner: "virustotal",
      displayName: "VirusTotal",
      verdict,
      score,
      durationMs: Date.now() - started,
      summary: `VT live: ${stats.malicious} malicious / ${stats.suspicious} suspicious / ${stats.harmless + stats.undetected} clean.`,
      findings,
      meta: {
        mode: "live",
        sha256,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
      },
    };
  }

  const emu = emulateVirusTotal(buf, fileName);
  const score = Math.max(0, 100 - emu.malicious * 8 - emu.suspicious * 3);
  const verdict =
    emu.malicious >= 8
      ? "malicious"
      : emu.malicious > 0 || emu.suspicious > 5
        ? "suspicious"
        : "clean";

  return {
    scanner: "virustotal",
    displayName: "VirusTotal",
    verdict,
    score,
    durationMs: Date.now() - started,
    summary:
      process.env.VIRUSTOTAL_API_KEY
        ? "VirusTotal API unreachable — local multi-engine emulation used."
        : "Set VIRUSTOTAL_API_KEY for live VT. Using multi-engine emulation.",
    findings: emu.findings,
    meta: {
      mode: "emulated",
      sha256,
      malicious: emu.malicious,
      suspicious: emu.suspicious,
      names: emu.names.join(",") || "none",
    },
  };
}
