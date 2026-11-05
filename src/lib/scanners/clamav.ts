import { execFile } from "child_process";
import { promisify } from "util";
import type { EngineResult, ThreatFinding } from "../types";

const execFileAsync = promisify(execFile);

/**
 * Native ClamAV, no signature emulation.
 *
 * Preferred path: `clamdscan` against a running clamd (signature DB stays loaded
 * in memory, a scan costs milliseconds of setup). Fallback: `clamscan`, which
 * reloads the whole database on every invocation and is much slower.
 *
 * ClamAV and ClamWin both use the same ClamAV signature DB, so one scan result
 * is shared between the two engines instead of running the scanner twice.
 */

type ClamOutcome =
  | { kind: "clean"; engine: string; raw: string }
  | { kind: "infected"; engine: string; signature: string; raw: string }
  | { kind: "error"; engine?: string; message: string };

const SCAN_TIMEOUT_MS = 120_000;

type ExecError = {
  code?: number | string;
  stdout?: string;
  stderr?: string;
  message?: string;
};

/**
 * Only a real `<path>: <signature> FOUND` line counts as an infection. A
 * non-zero exit without that line (e.g. missing DB) is an error, never malware.
 */
function parseInfected(out: string, engine: string): ClamOutcome | null {
  const line = out
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /:\s.+\sFOUND$/i.test(l));
  if (!line) return null;
  const signature =
    line.replace(/^.+:\s*/, "").replace(/\s+FOUND$/i, "").trim() ||
    "ClamAV detection";
  return { kind: "infected", engine, signature, raw: line };
}

/**
 * Scan through clamd. Returns null when the daemon is not reachable so the
 * caller can fall back to clamscan. Exit codes: 0 clean, 1 infected, 2 error.
 */
async function scanWithClamd(filePath: string): Promise<ClamOutcome | null> {
  try {
    const { stdout, stderr } = await execFileAsync(
      "clamdscan",
      ["--fdpass", "--no-summary", "--infected", filePath],
      { timeout: SCAN_TIMEOUT_MS, maxBuffer: 4_000_000 },
    );
    return {
      kind: "clean",
      engine: "clamdscan",
      raw: `${stdout}\n${stderr}`.trim(),
    };
  } catch (err: unknown) {
    const e = err as ExecError;
    const out = `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message ?? ""}`;
    if (e.code === 1) {
      const infected = parseInfected(out, "clamdscan");
      if (infected) return infected;
    }
    // 2 = clamd unreachable / daemon error, ENOENT = clamdscan not installed
    if (e.code === 2 || e.code === "ENOENT") return null;
    return {
      kind: "error",
      engine: "clamdscan",
      message: `ClamAV (clamd) failed: ${out.trim().slice(0, 400) || "unknown error"}`,
    };
  }
}

/** Resolved once per process: is a standalone clamscan binary available? */
let clamscanAvailable: Promise<boolean> | null = null;
function hasClamscan(): Promise<boolean> {
  clamscanAvailable ??= execFileAsync("clamscan", ["--version"], {
    timeout: 4000,
  }).then(
    () => true,
    () => false,
  );
  return clamscanAvailable;
}

async function scanWithClamscan(
  filePath: string,
): Promise<ClamOutcome> {
  if (!(await hasClamscan())) {
    return {
      kind: "error",
      message:
        "ClamAV DB: clamd and clamscan are unavailable — the antivirus must not be bypassed by emulation.",
    };
  }
  try {
    const { stdout, stderr } = await execFileAsync(
      "clamscan",
      ["--infected", "--no-summary", "--database=/var/lib/clamav", filePath],
      { timeout: SCAN_TIMEOUT_MS, maxBuffer: 4_000_000 },
    );
    return { kind: "clean", engine: "clamscan", raw: `${stdout}\n${stderr}`.trim() };
  } catch (err: unknown) {
    const e = err as ExecError;
    const out = `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message ?? ""}`;
    // clamscan exits 1 when infected (only trusted with a FOUND line)
    if (e.code === 1) {
      const infected = parseInfected(out, "clamscan");
      if (infected) return infected;
    }
    return {
      kind: "error",
      engine: "clamscan",
      message: `ClamAV DB failed: ${out.trim().slice(0, 400) || "unknown error"}`,
    };
  }
}

async function runNativeClam(filePath: string): Promise<ClamOutcome> {
  const viaDaemon = await scanWithClamd(filePath);
  if (viaDaemon) return viaDaemon;
  return scanWithClamscan(filePath);
}

function infectedResult(
  scanner: "clamav" | "clamwin",
  displayName: string,
  started: number,
  signature: string,
  engine: string,
): EngineResult {
  const findings: ThreatFinding[] = [
    {
      id: `${scanner}-found`,
      scanner,
      severity: "critical",
      title: `${displayName}: ${signature}`,
      detail: `Native signature from the ClamAV database (${engine}).`,
      category: /stealer|trojan|spyware/i.test(signature)
        ? /stealer/i.test(signature)
          ? "stealer"
          : "trojan"
        : "virus",
    },
  ];
  return {
    scanner,
    displayName,
    verdict: "malicious",
    score: 0,
    durationMs: Date.now() - started,
    summary: `${displayName} detected a threat: ${signature}`,
    findings,
    meta: { mode: "native", engine, signature },
  };
}

function cleanResult(
  scanner: "clamav" | "clamwin",
  displayName: string,
  started: number,
  engine: string,
  summary: string,
): EngineResult {
  return {
    scanner,
    displayName,
    verdict: "clean",
    score: 100,
    durationMs: Date.now() - started,
    summary,
    findings: [],
    meta: { mode: "native", engine },
  };
}

function errorResult(
  scanner: "clamav" | "clamwin",
  displayName: string,
  started: number,
  message: string,
): EngineResult {
  return {
    scanner,
    displayName,
    verdict: "error",
    score: 0,
    durationMs: Date.now() - started,
    summary: message,
    findings: [
      {
        id: `${scanner}-error`,
        scanner,
        severity: "high",
        title: `${displayName} unavailable`,
        detail: message,
        category: "policy",
      },
    ],
    meta: { mode: "unavailable" },
  };
}

/**
 * Runs the ClamAV signature scan once and returns both the ClamAV and the
 * ClamWin engine results (ClamWin is the same DB, reported separately).
 */
export async function runClamSuite(
  filePath: string,
  fileName: string,
): Promise<[EngineResult, EngineResult]> {
  const started = Date.now();
  const outcome = await runNativeClam(filePath);

  const clamav = (() => {
    if (outcome.kind === "clean") {
      return cleanResult(
        "clamav",
        "ClamAV",
        started,
        outcome.engine,
        "ClamAV (native): no known signatures found.",
      );
    }
    if (outcome.kind === "infected") {
      return infectedResult("clamav", "ClamAV", started, outcome.signature, outcome.engine);
    }
    return errorResult("clamav", "ClamAV", started, outcome.message);
  })();

  const isWindows = /\.(exe|dll|msi|scr|com|cpl)$/i.test(fileName);
  const clamwinName = "ClamWin (ClamAV DB)";
  const clamwin = (() => {
    if (outcome.kind === "clean") {
      return cleanResult(
        "clamwin",
        clamwinName,
        started,
        outcome.engine,
        isWindows
          ? "ClamWin/ClamAV DB (native): Windows build is clean by signatures."
          : "ClamWin/ClamAV DB (native): no signatures found.",
      );
    }
    if (outcome.kind === "infected") {
      return infectedResult("clamwin", clamwinName, started, outcome.signature, outcome.engine);
    }
    return errorResult("clamwin", clamwinName, started, outcome.message);
  })();

  return [clamav, clamwin];
}
