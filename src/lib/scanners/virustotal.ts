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

function statsHaveVendors(stats: VtStats): boolean {
  const total =
    (stats.malicious ?? 0) +
    (stats.suspicious ?? 0) +
    (stats.harmless ?? 0) +
    (stats.undetected ?? 0) +
    (stats.timeout ?? 0) +
    (stats.failure ?? 0) +
    (stats["type-unsupported"] ?? 0);
  return total > 0;
}

async function getFileReport(sha256: string): Promise<{
  stats: VtStats;
  names: string[];
  permalink?: string;
  ready: boolean;
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
    ready: statsHaveVendors(stats),
  };
}

async function pollAnalysis(
  analysisId: string,
  opts: { attempts: number; intervalMs: number },
): Promise<VtStats | undefined> {
  for (let i = 0; i < opts.attempts; i++) {
    await new Promise((r) => setTimeout(r, opts.intervalMs));
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
    if (
      aj.data?.attributes?.status === "completed" &&
      aj.data.attributes.stats &&
      statsHaveVendors(aj.data.attributes.stats)
    ) {
      return aj.data.attributes.stats;
    }
  }
  return undefined;
}

async function uploadFile(
  buf: Buffer,
  fileName: string,
): Promise<string> {
  const form = new FormData();
  form.append(
    "file",
    new Blob([new Uint8Array(buf)]),
    fileName || "upload.bin",
  );

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
    upload = await fetch(uploadUrl, {
      method: "POST",
      headers: { "x-apikey": vtKey()! },
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
    throw new Error("VirusTotal rate limit (public API 4 req/min) — подождите минуту и нажмите «Перепроверить»");
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
  return analysisId;
}

function pendingResult(
  started: number,
  sha256: string,
  fileName: string,
  bytes: number,
  analysisId?: string,
): EngineResult {
  const mb = (bytes / 1024 / 1024).toFixed(0);
  const permalink = `https://www.virustotal.com/gui/file/${sha256}`;
  const findings: ThreatFinding[] = [
    {
      id: "vt-pending",
      scanner: "virustotal",
      severity: "medium",
      title: "VirusTotal ещё анализирует файл",
      detail: `Файл «${fileName}» (~${mb} МБ) загружен в VirusTotal, но вендоры не успели вернуть вердикты. Это не детект вируса и не уязвимость — анализ крупного .exe часто занимает несколько минут.`,
      category: "policy",
      meaning:
        "Публичный API VirusTotal принимает файл, затем десятки антивирусов сканируют его асинхронно. Пока отчёт пустой — мы не знаем, чистый файл или нет по VT.",
      action:
        "Подождите 1–3 минуты и нажмите «Перепроверить VirusTotal». Либо откройте отчёт на VirusTotal по ссылке SHA256.",
    },
  ];
  return {
    scanner: "virustotal",
    displayName: "VirusTotal",
    verdict: "error",
    score: 40,
    durationMs: Date.now() - started,
    summary: `VirusTotal: анализ ещё идёт (~${mb} МБ). Это таймаут ожидания, не malware.`,
    findings,
    meta: {
      mode: "pending-analysis",
      sha256,
      bytes,
      permalink,
      ...(analysisId ? { analysisId } : {}),
      actionable: true,
    },
  };
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
  const permalink = `https://www.virustotal.com/gui/file/${sha256}`;

  if (stats.malicious > 0) {
    findings.push({
      id: "vt-malicious",
      scanner: "virustotal",
      severity: stats.malicious >= 5 ? "critical" : "high",
      title: `${stats.malicious} движков VirusTotal отметили malware`,
      detail: names.length
        ? `Популярные имена угроз: ${names.slice(0, 8).join(", ")}. Полный разбор: ${permalink}`
        : `Смотрите разбор вендоров: ${permalink}`,
      category: "virus",
      meaning:
        "Несколько независимых антивирусов в VirusTotal считают файл вредоносным (вирус, троян, стиллер и т.п.).",
      action:
        "Не публикуйте сборку. Проверьте цепочку сборки, зависимости и подпись кода. Сверьте отчёт на VirusTotal по вендорам.",
    });
  } else if ((stats.suspicious ?? 0) > 2) {
    findings.push({
      id: "vt-suspicious",
      scanner: "virustotal",
      severity: "medium",
      title: `${stats.suspicious} движков отметили suspicious`,
      detail: `Вендоры не уверены. Отчёт: ${permalink}`,
      category: "other",
      meaning:
        "Часть антивирусов видит подозрительное поведение, но это ещё не подтверждённый malware.",
      action:
        "Изучите отчёт VT, уберите упаковщики/ложные срабатывания, пересоберите и перепроверьте.",
    });
  }

  const score = Math.max(
    0,
    100 - stats.malicious * 8 - (stats.suspicious ?? 0) * 3,
  );
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
    summary:
      verdict === "clean"
        ? `VirusTotal: чисто — ${stats.malicious} malicious / ${stats.suspicious ?? 0} suspicious / ${cleanish} clean.`
        : `VirusTotal (${mode}): ${stats.malicious} malicious / ${stats.suspicious ?? 0} suspicious / ${cleanish} clean.`,
    findings,
    meta: {
      mode,
      sha256,
      malicious: stats.malicious,
      suspicious: stats.suspicious ?? 0,
      permalink,
      ...extra,
    },
  };
}

/**
 * VirusTotal Public API — hash lookup, upload, long poll for large files.
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
      summary: "VIRUSTOTAL_API_KEY не задан — публичный API недоступен.",
      findings: [
        {
          id: "vt-no-key",
          scanner: "virustotal",
          severity: "high",
          title: "VirusTotal не настроен",
          detail: "Ключ API отсутствует на сервере.",
          category: "policy",
          meaning: "Без ключа мы не можем спросить VirusTotal.",
          action: "Добавьте VIRUSTOTAL_API_KEY в окружение сервера.",
        },
      ],
      meta: { mode: "unavailable", sha256 },
    };
  }

  try {
    const existing = await getFileReport(sha256);
    if (existing?.ready) {
      return toResult(
        started,
        sha256,
        existing.stats,
        existing.names,
        "hash-lookup",
      );
    }

    // File known but vendors empty → still analyzing
    let analysisId: string | undefined;
    if (!existing) {
      analysisId = await uploadFile(buf, fileName);
    }

    const large = buf.length > 32 * 1024 * 1024;
    const attempts = large ? 48 : 30; // large: ~4 min, small: ~90s
    const intervalMs = large ? 5000 : 3000;

    if (analysisId) {
      const stats = await pollAnalysis(analysisId, { attempts, intervalMs });
      if (stats) {
        const report = await getFileReport(sha256);
        return toResult(
          started,
          sha256,
          report?.ready ? report.stats : stats,
          report?.names ?? [],
          large ? "large-upload+analyze" : "upload+analyze",
          { analysisId, bytes: buf.length },
        );
      }
    } else {
      // Already on VT but empty — wait by re-fetching hash
      for (let i = 0; i < attempts; i++) {
        await new Promise((r) => setTimeout(r, intervalMs));
        const again = await getFileReport(sha256);
        if (again?.ready) {
          return toResult(
            started,
            sha256,
            again.stats,
            again.names,
            "hash-lookup-wait",
            { bytes: buf.length },
          );
        }
      }
    }

    // Final hash check before declaring pending
    const last = await getFileReport(sha256);
    if (last?.ready) {
      return toResult(started, sha256, last.stats, last.names, "hash-lookup-late");
    }

    return pendingResult(started, sha256, fileName, buf.length, analysisId);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: "virustotal",
      displayName: "VirusTotal",
      verdict: "error",
      score: 0,
      durationMs: Date.now() - started,
      summary: `Ошибка VirusTotal: ${message}`,
      findings: [
        {
          id: "vt-error",
          scanner: "virustotal",
          severity: "high",
          title: "Сбой запроса к VirusTotal",
          detail: message.slice(0, 400),
          category: "policy",
          meaning:
            "Это техническая ошибка API/сети, а не вердикт «файл заражён».",
          action:
            "Повторите скан кнопкой «Перепроверить VirusTotal». Если ошибка rate limit — подождите ~60 секунд.",
        },
      ],
      meta: { mode: "error", sha256 },
    };
  }
}
