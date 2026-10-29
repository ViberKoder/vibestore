import { createHash } from "crypto";
import type { EngineResult, ThreatFinding } from "../types";

interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
  failure?: number;
  "type-unsupported"?: number;
}

function vtKey(): string | undefined {
  const key = process.env.VIRUSTOTAL_API_KEY?.trim();
  return key || undefined;
}

async function vtFetch(path: string, init?: RequestInit): Promise<Response> {
  const key = vtKey();
  if (!key) throw new Error("VIRUSTOTAL_API_KEY is not set");
  return fetch(`https://www.virustotal.com/api/v3${path}`, {
    ...init,
    headers: {
      "x-apikey": key,
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
}

async function getFileReport(sha256: string): Promise<{
  stats: VtStats;
  names: string[];
  permalink?: string;
} | null> {
  const res = await vtFetch(`/files/${sha256}`);
  if (res.status === 404) return null;
  if (res.status === 401 || res.status === 403) {
    throw new Error(`VirusTotal auth failed (${res.status})`);
  }
  if (!res.ok) {
    throw new Error(`VirusTotal report error ${res.status}`);
  }
  const json = (await res.json()) as {
    data?: {
      id?: string;
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
  return {
    stats,
    names,
    permalink: `https://www.virustotal.com/gui/file/${sha256}`,
  };
}

async function uploadAndAnalyze(
  buf: Buffer,
  fileName: string,
): Promise<{ stats: VtStats; names: string[]; analysisId: string; sha256: string }> {
  const form = new FormData();
  form.append(
    "file",
    new Blob([new Uint8Array(buf)]),
    fileName || "upload.bin",
  );

  // Free Public API: ≤32MB → /files ; larger → one-time upload_url (up to 650MB)
  let upload: Response;
  if (buf.length > 32 * 1024 * 1024) {
    const urlRes = await vtFetch("/files/upload_url");
    if (!urlRes.ok) {
      throw new Error(
        `VirusTotal upload_url failed ${urlRes.status} (нужен для файлов > 32 МБ)`,
      );
    }
    const urlJson = (await urlRes.json()) as { data?: string };
    const uploadUrl = urlJson.data;
    if (!uploadUrl) throw new Error("VirusTotal не вернул upload_url");
    const key = vtKey()!;
    upload = await fetch(uploadUrl, {
      method: "POST",
      headers: { "x-apikey": key },
      body: form,
      cache: "no-store",
    });
  } else {
    upload = await vtFetch("/files", { method: "POST", body: form });
  }

  if (upload.status === 401 || upload.status === 403) {
    throw new Error(`VirusTotal upload auth failed (${upload.status})`);
  }
  if (upload.status === 429) {
    throw new Error("VirusTotal rate limit (public API 4 req/min)");
  }
  if (!upload.ok) {
    const body = await upload.text();
    throw new Error(`VirusTotal upload failed ${upload.status}: ${body.slice(0, 200)}`);
  }

  const uploaded = (await upload.json()) as {
    data?: { id?: string; type?: string };
  };
  const analysisId = uploaded.data?.id;
  if (!analysisId) throw new Error("VirusTotal upload returned no analysis id");

  // Poll analysis until completed (public API can take a bit)
  let stats: VtStats | undefined;
  for (let i = 0; i < 24; i++) {
    await new Promise((r) => setTimeout(r, 2500));
    const poll = await vtFetch(`/analyses/${analysisId}`);
    if (!poll.ok) continue;
    const aj = (await poll.json()) as {
      data?: {
        attributes?: {
          status?: string;
          stats?: VtStats;
        };
      };
    };
    if (aj.data?.attributes?.status === "completed") {
      stats = aj.data.attributes.stats;
      break;
    }
  }

  if (!stats) {
    throw new Error("VirusTotal analysis timed out waiting for completion");
  }

  const sha256 = createHash("sha256").update(buf).digest("hex");
  // Prefer full file report for threat names once indexed
  try {
    const report = await getFileReport(sha256);
    if (report) {
      return {
        stats: report.stats,
        names: report.names,
        analysisId,
        sha256,
      };
    }
  } catch {
    /* keep analysis stats */
  }

  return { stats, names: [], analysisId, sha256 };
}

function toResult(
  started: number,
  sha256: string,
  stats: VtStats,
  names: string[],
  mode: string,
  extra?: Record<string, string | number | boolean>,
): EngineResult {
  const findings: ThreatFinding[] = [];
  if (stats.malicious > 0) {
    findings.push({
      id: "vt-malicious",
      scanner: "virustotal",
      severity: stats.malicious >= 5 ? "critical" : "high",
      title: `${stats.malicious} движков VirusTotal отметили malware`,
      detail: names.length
        ? `Популярные имена: ${names.slice(0, 5).join(", ")}`
        : `Отчёт: https://www.virustotal.com/gui/file/${sha256}`,
      category: "virus",
    });
  } else if ((stats.suspicious ?? 0) > 2) {
    findings.push({
      id: "vt-suspicious",
      scanner: "virustotal",
      severity: "medium",
      title: `${stats.suspicious} движков отметили suspicious`,
      detail: "Не подтверждённый malware, но вендоры расходятся.",
      category: "other",
    });
  }

  const score = Math.max(0, 100 - stats.malicious * 8 - (stats.suspicious ?? 0) * 3);
  const verdict =
    stats.malicious >= 3
      ? "malicious"
      : stats.malicious > 0 || (stats.suspicious ?? 0) > 2
        ? "suspicious"
        : "clean";

  const cleanish = (stats.harmless ?? 0) + (stats.undetected ?? 0);

  return {
    scanner: "virustotal",
    displayName: "VirusTotal",
    verdict,
    score,
    durationMs: Date.now() - started,
    summary: `VT Public API (${mode}): ${stats.malicious} malicious / ${stats.suspicious ?? 0} suspicious / ${cleanish} clean.`,
    findings,
    meta: {
      mode,
      sha256,
      malicious: stats.malicious,
      suspicious: stats.suspicious ?? 0,
      permalink: `https://www.virustotal.com/gui/file/${sha256}`,
      ...extra,
    },
  };
}

/**
 * VirusTotal Public API only — no local emulation bypass.
 * Flow: hash lookup → if unknown, upload file → poll analysis.
 */
export async function runVirusTotal(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const sha256 = createHash("sha256").update(buf).digest("hex");

  if (!vtKey()) {
    return {
      scanner: "virustotal",
      displayName: "VirusTotal",
      verdict: "error",
      score: 0,
      durationMs: Date.now() - started,
      summary:
        "VIRUSTOTAL_API_KEY не задан — публичный API недоступен. Добавьте ключ с https://www.virustotal.com/gui/my-apikey",
      findings: [
        {
          id: "vt-no-key",
          scanner: "virustotal",
          severity: "high",
          title: "VirusTotal не настроен",
          detail: "Сканирование через VT пропущено из‑за отсутствия API key.",
          category: "policy",
        },
      ],
      meta: { mode: "unavailable", sha256 },
    };
  }

  try {
    const existing = await getFileReport(sha256);
    if (existing) {
      return toResult(started, sha256, existing.stats, existing.names, "hash-lookup");
    }

    const analyzed = await uploadAndAnalyze(buf, fileName);
    const mode =
      buf.length > 32 * 1024 * 1024 ? "large-upload+analyze" : "upload+analyze";
    return toResult(
      started,
      analyzed.sha256,
      analyzed.stats,
      analyzed.names,
      mode,
      { analysisId: analyzed.analysisId, bytes: buf.length },
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: "virustotal",
      displayName: "VirusTotal",
      verdict: "error",
      score: 0,
      durationMs: Date.now() - started,
      summary: `VirusTotal Public API error: ${message}`,
      findings: [
        {
          id: "vt-error",
          scanner: "virustotal",
          severity: "high",
          title: "Ошибка VirusTotal API",
          detail: message.slice(0, 400),
          category: "policy",
        },
      ],
      meta: { mode: "error", sha256 },
    };
  }
}
