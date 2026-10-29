import { execFile } from "child_process";
import { promisify } from "util";
import type { EngineResult, ThreatFinding } from "../types";

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

type ClamOutcome =
  | { kind: "clean"; engine: string; raw: string }
  | { kind: "infected"; engine: string; signature: string; raw: string }
  | { kind: "error"; engine?: string; message: string };

async function runNativeClam(
  filePath: string,
  label: string,
): Promise<ClamOutcome> {
  const bin = await findClamscan();
  if (!bin) {
    return {
      kind: "error",
      message: `${label}: clamscan/clamdscan не установлен — антивирус нельзя обходить эмуляцией.`,
    };
  }

  try {
    const { stdout, stderr } = await execFileAsync(
      bin,
      [
        "--infected",
        "--no-summary",
        "--database=/var/lib/clamav",
        filePath,
      ],
      { timeout: 120_000, maxBuffer: 4_000_000 },
    );
    const out = `${stdout}\n${stderr}`.trim();
    return { kind: "clean", engine: bin, raw: out };
  } catch (err: unknown) {
    const e = err as {
      code?: number | string;
      stdout?: string;
      stderr?: string;
      message?: string;
    };
    const out = `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message ?? ""}`;
    // clamscan exits 1 when infected
    if (e.code === 1 || /FOUND/i.test(out)) {
      const line =
        out
          .split("\n")
          .map((l) => l.trim())
          .find((l) => /FOUND/i.test(l)) ?? out.slice(0, 300);
      const signature =
        line.replace(/^.+:\s*/, "").replace(/\s+FOUND.*$/i, "").trim() ||
        "ClamAV detection";
      return { kind: "infected", engine: bin, signature, raw: line };
    }
    return {
      kind: "error",
      engine: bin,
      message: `${label} failed: ${out.slice(0, 400) || "unknown error"}`,
    };
  }
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
      detail: `Нативная сигнатура из базы ClamAV (${engine}).`,
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
    summary: `${displayName} обнаружил угрозу: ${signature}`,
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
        title: `${displayName} недоступен`,
        detail: message,
        category: "policy",
      },
    ],
    meta: { mode: "unavailable" },
  };
}

/** Native ClamAV — no signature emulation bypass. */
export async function runClamAv(
  filePath: string,
  _buf: Buffer,
  _fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const outcome = await runNativeClam(filePath, "ClamAV");
  if (outcome.kind === "clean") {
    return cleanResult(
      "clamav",
      "ClamAV",
      started,
      outcome.engine,
      "ClamAV (native): известных сигнатур не найдено.",
    );
  }
  if (outcome.kind === "infected") {
    return infectedResult(
      "clamav",
      "ClamAV",
      started,
      outcome.signature,
      outcome.engine,
    );
  }
  return errorResult("clamav", "ClamAV", started, outcome.message);
}

/**
 * ClamWin uses the same ClamAV signature databases (Windows-oriented product).
 * On this host we run the same native clamscan DB — not a fake pass.
 */
export async function runClamWin(
  filePath: string,
  _buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const outcome = await runNativeClam(filePath, "ClamWin");
  const isWindows = /\.(exe|dll|msi|scr|com|cpl)$/i.test(fileName);

  if (outcome.kind === "clean") {
    return cleanResult(
      "clamwin",
      "ClamWin (ClamAV DB)",
      started,
      outcome.engine,
      isWindows
        ? "ClamWin/ClamAV DB (native): Windows-сборка чистая по сигнатурам."
        : "ClamWin/ClamAV DB (native): сигнатур не найдено.",
    );
  }
  if (outcome.kind === "infected") {
    return infectedResult(
      "clamwin",
      "ClamWin (ClamAV DB)",
      started,
      outcome.signature,
      outcome.engine,
    );
  }
  return errorResult("clamwin", "ClamWin (ClamAV DB)", started, outcome.message);
}
