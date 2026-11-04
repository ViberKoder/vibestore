import { promises as fs } from "fs";
import { NextResponse } from "next/server";
import {
  finalizeReport,
  initialScanProgress,
  runScanPipeline,
  statusFromReport,
} from "@/lib/scanners/pipeline";
import { runVirusTotal } from "@/lib/scanners/virustotal";
import {
  getAppById,
  getAppBySlug,
  patchApp,
  updateScanProgress,
} from "@/lib/store";

export const runtime = "nodejs";
export const maxDuration = 600;

export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = (await getAppById(id)) ?? (await getAppBySlug(id));
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }
  if (!app.filePath) {
    return NextResponse.json({ error: "No file on disk" }, { status: 400 });
  }

  const url = new URL(req.url);
  const engine = url.searchParams.get("engine") ?? "all";

  let buffer: Buffer;
  try {
    buffer = await fs.readFile(app.filePath);
  } catch {
    return NextResponse.json({ error: "File missing" }, { status: 404 });
  }

  if (engine === "virustotal" && app.scan) {
    await updateScanProgress(app.id, {
      ...initialScanProgress(),
      phase: "running",
      label: "Перепроверяем VirusTotal…",
      percent: 40,
      currentEngine: "virustotal",
      engines: (app.scanProgress?.engines ?? initialScanProgress().engines).map(
        (e) =>
          e.scanner === "virustotal"
            ? { ...e, phase: "running", summary: "Запрос к VirusTotal…" }
            : e,
      ),
    });

    const vt = await runVirusTotal(buffer, app.fileName);
    // Keep prior engines; if older scans lack Stage A engines, fill from order
    // by only replacing VT — full rescan is needed for missing auditors.
    const engines = app.scan.engines.map((e) =>
      e.scanner === "virustotal" ? vt : e,
    );
    const hasVt = engines.some((e) => e.scanner === "virustotal");
    if (!hasVt) engines.push(vt);

    const scan = await finalizeReport(
      engines,
      app.scan.startedAt ?? new Date().toISOString(),
      {
        name: app.name,
        kind: app.kind,
        fileName: app.fileName,
        version: app.version,
        tagline: app.tagline,
      },
    );
    // Preserve scan id across VT-only refresh
    scan.id = app.scan.id;

    const updated = await patchApp(app.id, {
      scan,
      status: statusFromReport(scan),
      scanProgress: {
        phase: "done",
        label: scan.readinessLabel,
        percent: 100,
        engines: scan.engines.map((e) => ({
          scanner: e.scanner,
          displayName: e.displayName,
          phase: "done" as const,
          verdict: e.verdict,
          summary: e.summary,
        })),
        updatedAt: new Date().toISOString(),
      },
    });
    return NextResponse.json({ app: updated, rescanned: "virustotal" });
  }

  // Full rescan — all AV + Stage A auditors
  await updateScanProgress(app.id, {
    ...initialScanProgress(),
    phase: "running",
    label: "Полный повторный скан…",
    percent: 1,
  });

  const scan = await runScanPipeline({
    filePath: app.filePath,
    buffer,
    fileName: app.fileName,
    appName: app.name,
    appKind: app.kind,
    appVersion: app.version,
    appTagline: app.tagline,
    onProgress: async (progress) => {
      await updateScanProgress(app.id, progress);
    },
  });

  const updated = await patchApp(app.id, {
    scan,
    status: statusFromReport(scan),
    scanProgress: {
      phase: "done",
      label: scan.readinessLabel,
      percent: 100,
      engines: scan.engines.map((e) => ({
        scanner: e.scanner,
        displayName: e.displayName,
        phase: "done" as const,
        verdict: e.verdict,
        summary: e.summary,
      })),
      updatedAt: new Date().toISOString(),
    },
  });

  return NextResponse.json({ app: updated, rescanned: "all" });
}
