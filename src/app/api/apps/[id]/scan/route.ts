import { promises as fs } from "fs";
import { NextResponse } from "next/server";
import {
  initialScanProgress,
  runScanPipeline,
  statusFromReport,
} from "@/lib/scanners/pipeline";
import { getAppById, getAppBySlug, patchApp, updateScanProgress } from "@/lib/store";

export const runtime = "nodejs";
export const maxDuration = 600;

const running = new Set<string>();

export async function POST(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = (await getAppById(id)) ?? (await getAppBySlug(id));
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }

  if (running.has(app.id)) {
    return NextResponse.json({
      app,
      alreadyRunning: true,
    });
  }

  if (!app.filePath) {
    return NextResponse.json({ error: "No file on disk" }, { status: 400 });
  }

  running.add(app.id);
  try {
    await updateScanProgress(app.id, {
      ...initialScanProgress(),
      phase: "running",
      label: "Запуск конвейера антивирусов…",
      percent: 1,
    });

    let buffer: Buffer;
    try {
      buffer = await fs.readFile(app.filePath);
    } catch {
      await patchApp(app.id, {
        status: "rejected",
        scanProgress: {
          phase: "error",
          label: "Файл сборки не найден на диске",
          percent: 0,
          engines: [],
          error: "missing file",
          updatedAt: new Date().toISOString(),
        },
      });
      return NextResponse.json({ error: "File missing" }, { status: 404 });
    }

    const scan = await runScanPipeline({
      filePath: app.filePath,
      buffer,
      fileName: app.fileName,
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
        engines:
          scan.engines.map((e) => ({
            scanner: e.scanner,
            displayName: e.displayName,
            phase: "done" as const,
            verdict: e.verdict,
            summary: e.summary,
          })),
        updatedAt: new Date().toISOString(),
      },
    });

    return NextResponse.json({ app: updated });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await patchApp(app.id, {
      status: "quarantined",
      scanProgress: {
        phase: "error",
        label: `Ошибка сканирования: ${message}`,
        percent: 0,
        engines: app.scanProgress?.engines ?? [],
        error: message,
        updatedAt: new Date().toISOString(),
      },
    });
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    running.delete(app.id);
  }
}
