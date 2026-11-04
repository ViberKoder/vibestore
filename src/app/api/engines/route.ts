import { execFile } from "child_process";
import { promisify } from "util";
import { NextResponse } from "next/server";
import { connection } from "next/server";

const execFileAsync = promisify(execFile);

export async function GET() {
  await connection();

  let clamav: { ok: boolean; version?: string; detail: string } = {
    ok: false,
    detail: "not found",
  };
  try {
    const { stdout } = await execFileAsync("clamscan", ["--version"], {
      timeout: 4000,
    });
    clamav = {
      ok: true,
      version: stdout.trim().split("\n")[0],
      detail: "native clamscan ready (/var/lib/clamav)",
    };
  } catch (err) {
    clamav = {
      ok: false,
      detail: err instanceof Error ? err.message : "clamscan missing",
    };
  }

  const vtKey = Boolean(process.env.VIRUSTOTAL_API_KEY?.trim());

  return NextResponse.json({
    virustotal: {
      ok: vtKey,
      mode: "public-api-v3",
      detail: vtKey
        ? "VIRUSTOTAL_API_KEY set — hash lookup + upload"
        : "Set VIRUSTOTAL_API_KEY (https://www.virustotal.com/gui/my-apikey)",
    },
    clamav,
    clamwin: {
      ok: clamav.ok,
      detail: clamav.ok
        ? "Uses native ClamAV signature DB (ClamWin-compatible)"
        : "Blocked until ClamAV is installed",
    },
    vibeguard: { ok: true, detail: "proprietary heuristics always on" },
    entropy: { ok: true, detail: "always on" },
    peInspector: { ok: true, detail: "always on" },
    networkSink: { ok: true, detail: "always on" },
    webStatic: { ok: true, detail: "always on" },
  });
}
