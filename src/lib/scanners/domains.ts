/**
 * External host categorisation for shipped code. The categories are heuristics:
 * a host is only as trustworthy as the list below, so the report says so.
 */
export type DomainCategory = "c2" | "ads" | "analytics" | "cdn" | "code-host" | "unclassified";

const RULES: Array<{ cat: DomainCategory; re: RegExp }> = [
  // Command-and-control / exfiltration channels frequently abused by stealers
  { cat: "c2", re: /(^|\.)discord(app)?\.com$|(^|\.)api\.telegram\.org$|(^|\.)pastebin\.com$|(^|\.)ngrok(-free)?\.(io|app)$|(^|\.)trycloudflare\.com$|(^|\.)webhook\.site$|(^|\.)requestbin\.|(^|\.)transfer\.sh$|(^|\.)hastebin\.com$|(^|\.)ghostbin\.|(^|\.)serveo\.net$|(^|\.)localtunnel\.me$/ },
  { cat: "ads", re: /(^|\.)doubleclick\.net$|(^|\.)googlesyndication\.com$|(^|\.)adservice\.google\.|(^|\.)admob\.com$|(^|\.)adjust\.(com|io)$|(^|\.)appsflyer\.com$|(^|\.)applovin\.com$|(^|\.)ironsrc\.com$|(^|\.)unity3d\.com$|(^|\.)unityads\.unity3d\.com$/ },
  { cat: "analytics", re: /(^|\.)google-analytics\.com$|(^|\.)googletagmanager\.com$|(^|\.)hotjar\.com$|(^|\.)mixpanel\.com$|(^|\.)segment\.(io|com)$|(^|\.)sentry\.io$|(^|\.)amplitude\.com$|(^|\.)fullstory\.com$|(^|\.)clarity\.ms$|(^|\.)connect\.facebook\.net$|(^|\.)facebook\.com$|(^|\.)datadoghq\.com$|(^|\.)bugsnag\.com$/ },
  { cat: "cdn", re: /(^|\.)jsdelivr\.net$|(^|\.)unpkg\.com$|(^|\.)cdnjs\.cloudflare\.com$|(^|\.)fonts\.(googleapis|gstatic)\.com$|(^|\.)googleapis\.com$|(^|\.)gstatic\.com$/ },
  { cat: "code-host", re: /(^|\.)github\.com$|(^|\.)githubusercontent\.com$|(^|\.)gitlab\.com$/ },
];

/** Namespace/schema URLs that appear in code and are not network endpoints. */
const NOISE = /(^|\.)w3\.org$|(^|\.)schema\.org$|(^|\.)reactjs\.org$|(^|\.)example\.(com|org)$|(^|\.)localhost$|(^|\.)xmlns\.com$|(^|\.)json-schema\.org$|(^|\.)mozilla\.org$|(^|\.)npmjs\.(org|com)$|(^|\.)nodejs\.org$|(^|\.)electronjs\.org$|(^|\.)opensource\.org$/;

export function extractHosts(text: string): Map<string, number> {
  const hosts = new Map<string, number>();
  const re = /(?:https?|wss?):\/\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)(?::\d+)?/gi;
  for (const m of text.matchAll(re)) {
    const host = m[1].toLowerCase();
    if (NOISE.test(host)) continue;
    hosts.set(host, (hosts.get(host) ?? 0) + 1);
    if (hosts.size > 5000) break;
  }
  return hosts;
}

export function categorise(host: string): DomainCategory {
  for (const r of RULES) if (r.re.test(host)) return r.cat;
  return "unclassified";
}

export function groupByCategory(hosts: Map<string, number>): Record<DomainCategory, string[]> {
  const out: Record<DomainCategory, string[]> = {
    c2: [],
    ads: [],
    analytics: [],
    cdn: [],
    "code-host": [],
    unclassified: [],
  };
  for (const h of hosts.keys()) out[categorise(h)].push(h);
  return out;
}
