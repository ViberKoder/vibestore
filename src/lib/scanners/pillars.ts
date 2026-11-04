import type { AuditPillars, EngineResult, ThreatFinding } from "../types";

const PILLAR_ENGINES: Record<keyof AuditPillars, string[]> = {
  safety: ["clamav", "clamwin", "virustotal", "vibeguard"],
  privacy: ["privacy", "network-sink"],
  hardening: [
    "secrets",
    "electron-hardening",
    "web-static",
    "pe-inspector",
  ],
  integrity: ["integrity", "entropy"],
  device: ["device-footprint"],
};

function weightedEngineScore(engines: EngineResult[], ids: string[]): number {
  const set = new Set(ids);
  const active = engines.filter(
    (e) => set.has(e.scanner) && e.verdict !== "skipped",
  );
  if (!active.length) return 100;
  const weights: Record<string, number> = {
    virustotal: 1.5,
    clamav: 1.2,
    clamwin: 1.0,
    vibeguard: 1.4,
    privacy: 1.3,
    "network-sink": 1.0,
    secrets: 1.5,
    "electron-hardening": 1.4,
    "web-static": 1.1,
    "pe-inspector": 0.9,
    integrity: 1.2,
    entropy: 0.6,
    "device-footprint": 1.3,
  };
  let sum = 0;
  let w = 0;
  for (const e of active) {
    const weight = weights[e.scanner] ?? 1;
    // Pending VT shouldn't crush Safety to zero the same way as malware
    const score =
      e.scanner === "virustotal" && e.meta?.mode === "pending-analysis"
        ? Math.max(e.score, 70)
        : e.score;
    sum += score * weight;
    w += weight;
  }
  return Math.round(sum / w);
}

export function computeAuditPillars(engines: EngineResult[]): AuditPillars {
  return {
    safety: weightedEngineScore(engines, PILLAR_ENGINES.safety),
    privacy: weightedEngineScore(engines, PILLAR_ENGINES.privacy),
    hardening: weightedEngineScore(engines, PILLAR_ENGINES.hardening),
    integrity: weightedEngineScore(engines, PILLAR_ENGINES.integrity),
    device: weightedEngineScore(engines, PILLAR_ENGINES.device),
  };
}

export function trustFromPillars(
  pillars: AuditPillars,
  findings: ThreatFinding[],
): number {
  // Overall trust blends pillars; Safety weighs most.
  const blended = Math.round(
    pillars.safety * 0.34 +
      pillars.hardening * 0.22 +
      pillars.privacy * 0.16 +
      pillars.integrity * 0.14 +
      pillars.device * 0.14,
  );
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  if (critical > 0) return Math.min(blended, 40);
  if (high > 0) return Math.min(blended, 72);
  return blended;
}

export { PILLAR_META } from "../types";
