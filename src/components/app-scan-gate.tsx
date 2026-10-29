"use client";

import { useRouter } from "next/navigation";
import { useCallback } from "react";
import type { StoreApp } from "@/lib/types";
import { ScanProgressPanel } from "./scan-progress-panel";
import { ScanReportView } from "./scan-report";

export function AppScanGate({
  app,
  forceScanning,
}: {
  app: StoreApp;
  forceScanning?: boolean;
}) {
  const router = useRouter();
  const scanning =
    forceScanning ||
    app.status === "scanning" ||
    app.status === "queued" ||
    (app.scanProgress?.phase === "running" ||
      app.scanProgress?.phase === "queued");

  const onFinished = useCallback(() => {
    router.replace(`/apps/${app.slug}`);
    router.refresh();
  }, [app.slug, router]);

  if (scanning && !app.scan) {
    return (
      <ScanProgressPanel
        appId={app.id}
        initial={app.scanProgress}
        autoStart
        onFinished={onFinished}
      />
    );
  }

  if (app.scanProgress?.phase === "running") {
    return (
      <div className="space-y-6">
        <ScanProgressPanel
          appId={app.id}
          initial={app.scanProgress}
          autoStart
          onFinished={onFinished}
        />
        {app.scan && <ScanReportView report={app.scan} appId={app.id} />}
      </div>
    );
  }

  if (app.scan) {
    return <ScanReportView report={app.scan} appId={app.id} />;
  }

  return (
    <div className="space-y-4">
      <p className="text-[14px] text-ink-2">
        Отчёт ещё не готов. Запускаем сканирование…
      </p>
      <ScanProgressPanel
        appId={app.id}
        initial={app.scanProgress}
        autoStart
        onFinished={onFinished}
      />
    </div>
  );
}
