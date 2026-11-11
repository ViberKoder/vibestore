import type { EngineResult, ScanReport, ThreatFinding } from "../types";
import { fetchPublic, parsePublicUrl } from "../security/net";
import { runNetworkSink, runVibeGuard, runWebStatic } from "./custom";
import { runPrivacyAuditor, runSecretsAuditor } from "./audit";
import { checkVirusTotalUrl } from "./virustotal";
import { finalizeReport } from "./pipeline";
import { categorise } from "./domains";

/**
 * Website checker. Fetches a public site with the SSRF-safe client, inspects the
 * response (TLS, headers, cookies, forms, mixed content), runs the content
 * detectors over the HTML and same-origin scripts, and asks VirusTotal about the URL.
 */

const MAX_PAGE = 2 * 1024 * 1024;
const MAX_SCRIPT = 1 * 1024 * 1024;
const MAX_SCRIPTS = 8;
const TIMEOUT = 12_000;

const F = (
  scanner: ThreatFinding["scanner"],
  id: string,
  severity: ThreatFinding["severity"],
  category: ThreatFinding["category"],
  title: string,
  detail: string,
  meaning: string,
  action: string,
): ThreatFinding => ({ id, scanner, severity, category, title, detail, meaning, action });

const regDomain = (host: string) => host.split(".").slice(-2).join(".");

function headerOf(h: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const v = h[name];
  return Array.isArray(v) ? v.join(", ") : v;
}

function httpSecurity(
  finalUrl: string,
  requestedUrl: string,
  status: number,
  headers: Record<string, string | string[] | undefined>,
  redirects: string[],
  html: string,
  thirdParty: string[],
): EngineResult {
  const started = Date.now();
  const findings: ThreatFinding[] = [];
  const page = new URL(finalUrl);
  const isHttps = page.protocol === "https:";

  if (!isHttps) {
    findings.push(F("http-security", "hs-no-https", "high", "vulnerability", "Site is served over plain HTTP",
      `${finalUrl} is not encrypted.`,
      "Credentials and cookies travel in clear text and can be altered on the network.",
      "Serve the site over HTTPS (a free certificate is available from most hosts)."));
  }
  if (status >= 400) {
    findings.push(F("http-security", "hs-status", "low", "other", `Site responded with HTTP ${status}`,
      "The checked page is an error page.",
      "The result describes an error response, not the product.",
      "Check the URL and the server configuration."));
  }
  const hops = [requestedUrl, ...redirects].map((u) => {
    try { return regDomain(new URL(u).hostname); } catch { return ""; }
  });
  if (new Set(hops.filter(Boolean)).size > 2) {
    findings.push(F("http-security", "hs-redirects", "medium", "policy", "Redirect chain crosses several domains",
      redirects.slice(0, 4).join(" → "),
      "Multi-domain redirects are used to hide the real destination of phishing and malware links.",
      "Link the final address directly."));
  }

  if (isHttps && !headerOf(headers, "strict-transport-security")) {
    findings.push(F("http-security", "hs-hsts", "low", "policy", "No HSTS header",
      "Strict-Transport-Security is missing.",
      "Without HSTS a first visit can be downgraded to plain HTTP.",
      "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."));
  }
  const csp = headerOf(headers, "content-security-policy");
  if (!csp) {
    findings.push(F("http-security", "hs-csp", "medium", "vulnerability", "No Content-Security-Policy",
      "No CSP header; any injected script runs with full page access.",
      "CSP is the main barrier against XSS and stolen sessions.",
      "Add a Content-Security-Policy that restricts script sources."));
  } else if (/'unsafe-eval'|'unsafe-inline'|\*\s*;/.test(csp)) {
    findings.push(F("http-security", "hs-csp-weak", "low", "vulnerability", "Weak Content-Security-Policy",
      csp.slice(0, 160),
      "unsafe-inline / unsafe-eval / wildcard sources largely defeat CSP.",
      "Use nonces or hashes instead of 'unsafe-inline' and drop 'unsafe-eval'."));
  }
  if (!headerOf(headers, "x-content-type-options")) {
    findings.push(F("http-security", "hs-nosniff", "low", "vulnerability", "No X-Content-Type-Options",
      "MIME sniffing is allowed.",
      "Browsers may execute uploaded files as scripts.",
      "Send X-Content-Type-Options: nosniff."));
  }
  const frameable = !headerOf(headers, "x-frame-options") && !/frame-ancestors/i.test(csp ?? "");
  if (frameable) {
    findings.push(F("http-security", "hs-clickjack", "low", "vulnerability", "Page can be framed (clickjacking)",
      "Neither X-Frame-Options nor frame-ancestors is set.",
      "A hostile page can overlay buttons on this site and trick users into clicks.",
      "Send frame-ancestors 'none' (or X-Frame-Options: DENY)."));
  }
  if (!headerOf(headers, "referrer-policy")) {
    findings.push(F("http-security", "hs-referrer", "info", "policy", "No Referrer-Policy",
      "Full URLs may leak to third parties.", "Minor privacy leak.", "Send Referrer-Policy: strict-origin-when-cross-origin."));
  }

  const cookies = ([] as string[]).concat(headers["set-cookie"] ?? []);
  const weak = cookies.filter((c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c));
  if (weak.length) {
    findings.push(F("http-security", "hs-cookies", "medium", "vulnerability", `${weak.length} cookie(s) without Secure/HttpOnly`,
      weak.slice(0, 2).map((c) => c.split("=")[0]).join(", "),
      "Session cookies without HttpOnly can be stolen by any injected script; without Secure they can leak over HTTP.",
      "Set Secure; HttpOnly; SameSite on session cookies."));
  }
  const disclosed = headerOf(headers, "x-powered-by") ?? headerOf(headers, "server");
  if (disclosed && /\d/.test(disclosed)) {
    findings.push(F("http-security", "hs-version", "info", "other", "Server version disclosed",
      disclosed.slice(0, 120),
      "Version banners help attackers pick known exploits.",
      "Hide or genericise the Server / X-Powered-By headers."));
  }

  // HTML: forms, mixed content
  const pageHost = page.hostname;
  const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)];
  for (const f of forms) {
    const hasPassword = /type\s*=\s*["']?password/i.test(f[2]);
    if (!hasPassword) continue;
    const action = /action\s*=\s*["']([^"']*)["']/i.exec(f[1])?.[1] ?? "";
    let target = pageHost;
    try { target = new URL(action, finalUrl).hostname; } catch { /* keep page host */ }
    const insecure = action.startsWith("http://") || (action && new URL(action, finalUrl).protocol === "http:");
    if (target !== pageHost || insecure) {
      findings.push(F("http-security", "hs-login-foreign", "high", "stealer", "Password form submits to another site",
        `Form action → ${target}${insecure ? " (plain HTTP)" : ""}`,
        "Login forms that post credentials elsewhere are the core of phishing kits.",
        "Post credentials only to your own HTTPS endpoint."));
      break;
    }
  }
  const mixed = [...html.matchAll(/<(script|link|img|iframe)\b[^>]*\s(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi)];
  if (mixed.length && isHttps) {
    findings.push(F("http-security", "hs-mixed", "medium", "vulnerability", `${mixed.length} plain-HTTP resource(s) on an HTTPS page`,
      "Scripts or styles loaded over HTTP can be replaced on the network.",
      "Mixed content lets attackers modify the page on the wire.",
      "Load every resource over HTTPS."));
  }

  if (thirdParty.length) {
    findings.push(F("http-security", "hs-third-party", "info", "policy", `${thirdParty.length} third-party script host(s)`,
      thirdParty.slice(0, 10).join(", "),
      "Every third-party script runs with the same access to the page as the site itself.",
      "Review each host; self-host what you can and add Subresource Integrity to the rest."));
  }

  const worst = findings.reduce((a, f) => Math.max(a, ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const)[f.severity]), 0);
  const penalty = findings.reduce((a, f) => a + ({ critical: 40, high: 22, medium: 10, low: 3, info: 0 } as const)[f.severity], 0);
  return {
    scanner: "http-security",
    displayName: "HTTP security",
    verdict: worst >= 2 ? "suspicious" : "clean",
    score: Math.max(0, 100 - penalty),
    durationMs: Date.now() - started,
    summary: findings.length ? `${findings.length} HTTP/TLS/header finding(s) on ${page.host}.` : `Headers and transport look good on ${page.host}.`,
    findings,
    meta: { status, finalUrl, https: isHttps },
  };
}

/** Same-origin scripts plus a few third-party ones, all public and size-capped. */
async function collectScripts(html: string, base: URL): Promise<Array<{ url: string; body: Buffer }>> {
  const srcs = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
  const abs = srcs
    .map((s) => { try { return new URL(s, base); } catch { return null; } })
    .filter((u): u is URL => Boolean(u) && (u!.protocol === "https:" || u!.protocol === "http:"));
  abs.sort((a, b) => Number(a.hostname !== base.hostname) - Number(b.hostname !== base.hostname));
  const out: Array<{ url: string; body: Buffer }> = [];
  for (const u of abs.slice(0, MAX_SCRIPTS)) {
    try {
      const r = await fetchPublic(u, { maxBytes: MAX_SCRIPT, timeoutMs: TIMEOUT, maxRedirects: 3 });
      if (r.status === 200 && r.body.length) out.push({ url: u.href, body: r.body });
    } catch {
      /* unreachable script: reported by the other engines as absent */
    }
  }
  return out;
}

export async function runWebsiteCheck(rawUrl: string): Promise<{ report: ScanReport; finalUrl: string }> {
  const startedAt = new Date().toISOString();
  const start = parsePublicUrl(rawUrl);
  const host = start.hostname;

  let page;
  try {
    page = await fetchPublic(start, { maxBytes: MAX_PAGE, timeoutMs: TIMEOUT, maxRedirects: 5 });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const unreachable: EngineResult = {
      scanner: "http-security",
      displayName: "HTTP security",
      verdict: "error",
      score: 0,
      durationMs: 0,
      summary: `Site could not be reached: ${message}`,
      findings: [F("http-security", "hs-unreachable", "high", "other", "Site could not be reached",
        message, "The checker could not read the site, so nothing about it can be verified.",
        "Make sure the site is public, online and serves HTTPS.")],
      meta: { mode: "error" },
    };
    const report = await finalizeReport([unreachable], startedAt, { name: host, kind: "web", fileName: start.href, version: "-", tagline: start.href });
    return { report, finalUrl: start.href };
  }

  const html = page.body.toString("utf8");
  const pageUrl = new URL(page.finalUrl);
  const headers = page.headers as Record<string, string | string[] | undefined>;

  const scripts = await collectScripts(html, pageUrl);
  const chunks: Buffer[] = [Buffer.from(html, "utf8")];
  scripts.forEach((s) => chunks.push(Buffer.from(`\n/*--- ${s.url} ---*/\n`, "utf8"), s.body));
  const content = Buffer.concat(chunks);

  const thirdParty = scripts.filter((s) => new URL(s.url).hostname !== pageUrl.hostname);
  const hosts = [...new Set(thirdParty.map((s) => new URL(s.url).hostname))];
  const categories = hosts.map((h) => `${h} (${categorise(h)})`);
  // hosts are shown with their category in the HTTP finding

  const [vibe, web, secrets, sink, privacy, vt] = await Promise.all([
    runVibeGuard(content, "index.html"),
    runWebStatic(content, "index.html"),
    runSecretsAuditor(content, "index.html"),
    runNetworkSink(content),
    runPrivacyAuditor(content),
    checkVirusTotalUrl(page.finalUrl),
  ]);

  const engines: EngineResult[] = [
    httpSecurity(page.finalUrl, rawUrl, page.status, headers, page.redirects, html, categories),
    vibe,
    web,
    secrets,
    sink,
    privacy,
    vt,
  ];
  const report = await finalizeReport(engines, startedAt, {
    name: pageUrl.hostname,
    kind: "web",
    fileName: pageUrl.href,
    version: "-",
    tagline: `Website check: ${pageUrl.href}`,
  });
  return { report, finalUrl: page.finalUrl };
}
