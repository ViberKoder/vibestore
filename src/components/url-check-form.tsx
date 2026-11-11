"use client";

import { useState } from "react";
import type { ScanReport } from "@/lib/types";
import { useT } from "@/lib/i18n/client";
import { ScanReportView } from "./scan-report";

export function UrlCheckForm() {
  const t = useT();
  const [url, setUrl] = useState("https://");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [finalUrl, setFinalUrl] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const json = (await res.json()) as { report?: ScanReport; finalUrl?: string; error?: string };
      if (!res.ok || !json.report) {
        setError(json.error ?? "Check failed");
      } else {
        setReport(json.report);
        setFinalUrl(json.finalUrl ?? null);
      }
    } catch {
      setError("Network unavailable");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={submit} className="flex flex-col gap-3 sm:flex-row">
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={busy}
          placeholder="https://example.com"
          className="field-input flex-1"
        />
        <button type="submit" disabled={busy} className="btn-primary">
          {busy ? t("Checking…") : t("Check site")}
        </button>
      </form>
      {error && (
        <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">{t(error)}</p>
      )}
      {report && (
        <div className="space-y-4">
          {finalUrl && (
            <p className="text-[13px] text-ink-3">
              {t("Checked address")}: <span className="font-mono text-ink">{finalUrl}</span>
            </p>
          )}
          <ScanReportView
            report={report}
            appName={finalUrl ?? undefined}
            appKind="web"
          />
        </div>
      )}
    </div>
  );
}
