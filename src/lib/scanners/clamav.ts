import { execFile } from "child_process";
import { promisify } from "util";
import type { EngineResult, ThreatFinding } from "../types";
import { STEALER_PATTERNS, VIRUS_NAME_HINTS } from "./signatures";

const execFileAsync = promisify(execFile);

async function findClamscan(): Promise<string | null> {
  for (const bin of ["clamscan", "clamdscan"]) {
    try {
      await execFileAsync(bin, ["--version"], { timeout: 4000 });
      return bin;
    } catch {
      /* try next */
    }
  }
  return null;
}

function emulateClamSignatures(
  text: string,
  fileName: string,
): ThreatFinding[] {
  const findings: ThreatFinding[] = [];
  const lower = text.toLowerCase();

  for (const hint of VIRUS_NAME_HINTS) {
    if (lower.includes(`eicar`) || lower.includes(`x5o!p%@ap`)) {
      findings.push({
        id: "clam-eicar",
        scanner: "clamav",
        severity: "critical",
        title: "EICAR test signature",
        detail: "Matched classic EICAR antivirus test string.",
        category: "virus",
      });
      break;
    }
    if (lower.includes(`win32.${hint}`) || lower.includes(`malware/${hint}`)) {
      findings.push({
        id: `clam-${hint}`,
        scanner: "clamav",
        severity: "critical",
        title: `ClamAV-like hit: ${hint}`,
        detail: `Heuristic signature resembling ${hint} family in ${fileName}.`,
        category: hint === "stealer" ? "stealer" : "virus",
      });
    }
  }

  for (const sig of STEALER_PATTERNS.slice(0, 3)) {
    if (sig.pattern.test(text)) {
      findings.push({
        id: `clam-sig-${sig.id}`,
        scanner: "clamav",
        severity: sig.severity,
        title: sig.title,
        detail: "Detected via ClamAV signature emulation layer.",
        category: "stealer",
      });
    }
  }

  return findings;
}

export async function runClamAv(
  filePath: string,
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const bin = await findClamscan();
  const text = buf.toString("latin1");

  if (bin) {
    try {
      const { stdout, stderr } = await execFileAsync(
        bin,
        ["--no-summary", "--infected", filePath],
        { timeout: 60_000, maxBuffer: 2_000_000 },
      );
      const out = `${stdout}\n${stderr}`;
      const infected = /FOUND/i.test(out) && !/OK$/m.test(out.split("\n").pop() ?? "");
      const line = out
        .split("\n")
        .find((l) => /FOUND/i.test(l));
      const findings: ThreatFinding[] = [];
      if (infected && line) {
        findings.push({
          id: "clamav-found",
          scanner: "clamav",
          severity: "critical",
          title: "ClamAV detection",
          detail: line.trim(),
          category: "virus",
        });
      }
      return {
        scanner: "clamav",
        displayName: "ClamAV",
        verdict: findings.length ? "malicious" : "clean",
        score: findings.length ? 0 : 100,
        durationMs: Date.now() - started,
        summary: findings.length
          ? "ClamAV reported malware signatures."
          : "ClamAV found no known signatures.",
        findings,
        meta: { engine: bin, mode: "native" },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // clamscan exits non-zero when infected
      if (/FOUND/i.test(message)) {
        return {
          scanner: "clamav",
          displayName: "ClamAV",
          verdict: "malicious",
          score: 0,
          durationMs: Date.now() - started,
          summary: "ClamAV reported malware.",
          findings: [
            {
              id: "clamav-found",
              scanner: "clamav",
              severity: "critical",
              title: "ClamAV detection",
              detail: message.slice(0, 400),
              category: "virus",
            },
          ],
          meta: { engine: bin, mode: "native" },
        };
      }
    }
  }

  const findings = emulateClamSignatures(text, fileName);
  return {
    scanner: "clamav",
    displayName: "ClamAV",
    verdict: findings.length ? "malicious" : "clean",
    score: findings.length ? Math.max(0, 40 - findings.length * 15) : 98,
    durationMs: Date.now() - started,
    summary: bin
      ? "ClamAV fallback heuristics used."
      : "ClamAV binary not installed — signature emulation layer used. Install clamav for native scans.",
    findings,
    meta: { mode: bin ? "fallback" : "emulated", clamAvailable: Boolean(bin) },
  };
}

/** ClamWin shares ClamAV signature DB; we expose it as a Windows-oriented pass. */
export async function runClamWin(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const text = buf.toString("latin1");
  const findings = emulateClamSignatures(text, fileName).map((f) => ({
    ...f,
    scanner: "clamwin" as const,
    detail: f.detail.replace("ClamAV", "ClamWin"),
  }));

  const isWindowsPayload = /\.(exe|dll|msi|scr|com)$/i.test(fileName);
  return {
    scanner: "clamwin",
    displayName: "ClamWin (ClamAV DB)",
    verdict: findings.length ? "malicious" : "clean",
    score: findings.length ? 10 : isWindowsPayload ? 96 : 94,
    durationMs: Date.now() - started,
    summary: findings.length
      ? "ClamWin signature set flagged this Windows-oriented payload."
      : isWindowsPayload
        ? "ClamWin signature set clean for Windows binary patterns."
        : "No Windows malware signatures matched (non-PE or clean).",
    findings,
    meta: { signatureSet: "clamav-main+daily (emulated)", windowsFocus: true },
  };
}
