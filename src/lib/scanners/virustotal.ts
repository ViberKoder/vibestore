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
        `VirusTotal upload_url failed ${urlRes.status} (needed for files > 32 MB)`,
      );
    }
    const urlJson = (await urlRes.json()) as { data?: string };
    const uploadUrl = urlJson.data;
    if (!uploadUrl) throw new Error("VirusTotal returned no upload_url");
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
    throw new Error("VirusTotal rate limit (public API 4 req/min) — wait a minute and press «Recheck»");
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
      title: "VirusTotal is still analyzing the file",
      detail: `File «${fileName}» (~${mb} MB) was uploaded to VirusTotal, but the vendors have not returned verdicts yet. This is not a virus detection or a vulnerability — analyzing a large .exe often takes several minutes.`,
      category: "policy",
      meaning:
        "The public VirusTotal API accepts the file, then dozens of antivirus engines scan it asynchronously. While the report is empty we do not know whether the file is clean on VT.",
      action:
        "Wait 1–3 minutes and press «Recheck VirusTotal». Or open the report on VirusTotal via the SHA256 link.",
    },
  ];
  return {
    scanner: "virustotal",
    displayName: "VirusTotal",
    verdict: "error",
    score: 40,
    durationMs: Date.now() - started,
    summary: `VirusTotal: analysis still in progress (~${mb} MB). This is a wait timeout, not malware.`,
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
      title: `${stats.malicious} VirusTotal engines flagged malware`,
      detail: names.length
        ? `Popular threat names: ${names.slice(0, 8).join(", ")}. Full report: ${permalink}`
        : `See the vendor breakdown: ${permalink}`,
      category: "virus",
      meaning:
        "Several independent antivirus engines in VirusTotal consider the file malicious (virus, trojan, stealer, etc.).",
      action:
        "Do not publish the build. Check the build chain, dependencies and code signature. Compare the VirusTotal vendor report.",
    });
  } else if ((stats.suspicious ?? 0) > 2) {
    findings.push({
      id: "vt-suspicious",
      scanner: "virustotal",
      severity: "medium",
      title: `${stats.suspicious} engines flagged suspicious`,
      detail: `Vendors are not sure. Report: ${permalink}`,
      category: "other",
      meaning:
        "Some antivirus engines see suspicious behavior, but this is not confirmed malware yet.",
      action:
        "Review the VT report, remove packers/false positives, rebuild and recheck.",
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
        ? `VirusTotal: clean — ${stats.malicious} malicious / ${stats.suspicious ?? 0} suspicious / ${cleanish} clean.`
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
      summary: "VIRUSTOTAL_API_KEY is not set — the public API is unavailable.",
      findings: [
        {
          id: "vt-no-key",
          scanner: "virustotal",
          severity: "high",
          title: "VirusTotal is not configured",
          detail: "The API key is missing on the server.",
          category: "policy",
          meaning: "Without a key we cannot query VirusTotal.",
          action: "Add VIRUSTOTAL_API_KEY to the server environment.",
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
      summary: `VirusTotal error: ${message}`,
      findings: [
        {
          id: "vt-error",
          scanner: "virustotal",
          severity: "high",
          title: "VirusTotal request failed",
          detail: message.slice(0, 400),
          category: "policy",
          meaning:
            "This is a technical API/network error, not a verdict that the file is infected.",
          action:
            "Repeat the scan with the «Recheck VirusTotal» button. If it is a rate limit error — wait about 60 seconds.",
        },
      ],
      meta: { mode: "error", sha256 },
    };
  }
}

/** VirusTotal URL reputation: existing report, otherwise submit and report as pending. */
export async function checkVirusTotalUrl(url: string): Promise<EngineResult> {
  const started = Date.now();
  if (!vtKey()) {
    return {
      scanner: "url-reputation",
      displayName: "VirusTotal (URL)",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "VirusTotal URL lookup skipped: VIRUSTOTAL_API_KEY is not set.",
      findings: [],
      meta: { mode: "unavailable" },
    };
  }
  const urlId = Buffer.from(url).toString("base64url");
  try {
    const res = await vtFetch(`/urls/${urlId}`);
    if (res.status === 404) {
      const body = new URLSearchParams({ url });
      const sub = await vtFetch("/urls", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      if (!sub.ok) throw new Error(`VirusTotal URL submit failed ${sub.status}`);
      return {
        scanner: "url-reputation",
        displayName: "VirusTotal (URL)",
        verdict: "error",
        score: 60,
        durationMs: Date.now() - started,
        summary: "VirusTotal: this URL was not analysed before. It has been submitted — check again in a few minutes.",
        findings: [
          {
            id: "url-vt-pending",
            scanner: "url-reputation",
            severity: "low",
            category: "policy",
            title: "VirusTotal is analysing this URL",
            detail: "The URL is new to VirusTotal. Vendors need a few minutes.",
            meaning: "Absence of a report is not a verdict.",
            action: "Run the check again later.",
          },
        ],
        meta: { mode: "pending-analysis" },
      };
    }
    if (res.status === 429) throw new Error("VirusTotal rate limit — try again in a minute");
    if (!res.ok) throw new Error(`VirusTotal URL report error ${res.status}`);
    const json = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: VtStats } };
    };
    const stats = json.data?.attributes?.last_analysis_stats;
    if (!stats) throw new Error("VirusTotal returned no stats");
    const perm = `https://www.virustotal.com/gui/url/${urlId}`;
    const bad = stats.malicious ?? 0;
    const susp = stats.suspicious ?? 0;
    const verdict: EngineResult["verdict"] = bad >= 3 ? "malicious" : bad > 0 || susp > 2 ? "suspicious" : "clean";
    const findings: ThreatFinding[] = [];
    if (bad > 0 || susp > 2) {
      findings.push({
        id: "url-vt-flagged",
        scanner: "url-reputation",
        severity: bad >= 3 ? "critical" : "high",
        category: "virus",
        title: `${bad} VirusTotal engine(s) flag this URL`,
        detail: `${bad} malicious / ${susp} suspicious. Report: ${perm}`,
        meaning: "Independent vendors consider this site dangerous.",
        action: "Do not link or distribute this URL. Check the vendor report.",
      });
    }
    return {
      scanner: "url-reputation",
      displayName: "VirusTotal (URL)",
      verdict,
      score: Math.max(0, 100 - bad * 10 - susp * 3),
      durationMs: Date.now() - started,
      summary: `VirusTotal URL: ${bad} malicious / ${susp} suspicious / ${stats.harmless ?? 0} harmless.`,
      findings,
      meta: { mode: "url-report", permalink: perm },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: "url-reputation",
      displayName: "VirusTotal (URL)",
      verdict: "error",
      score: 0,
      durationMs: Date.now() - started,
      summary: `VirusTotal URL error: ${message}`,
      findings: [],
      meta: { mode: "error" },
    };
  }
}
