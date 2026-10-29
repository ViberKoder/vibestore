export type AppKind = "desktop" | "web" | "cli" | "mobile" | "other";
export type AppStatus =
  | "queued"
  | "scanning"
  | "published"
  | "quarantined"
  | "rejected";

export type ThreatSeverity = "info" | "low" | "medium" | "high" | "critical";

export type ScannerId =
  | "clamav"
  | "clamwin"
  | "virustotal"
  | "vibeguard"
  | "entropy"
  | "pe-inspector"
  | "network-sink"
  | "web-static";

export type ScannerVerdict =
  | "clean"
  | "suspicious"
  | "malicious"
  | "error"
  | "skipped";

export type ReleaseReadiness = "ready" | "needs_fixes" | "blocked";

export interface ThreatFinding {
  id: string;
  scanner: ScannerId;
  severity: ThreatSeverity;
  title: string;
  detail: string;
  category:
    | "virus"
    | "trojan"
    | "stealer"
    | "adware"
    | "vulnerability"
    | "bug"
    | "packed"
    | "network"
    | "policy"
    | "other";
}

export interface EngineResult {
  scanner: ScannerId;
  displayName: string;
  verdict: ScannerVerdict;
  score: number;
  durationMs: number;
  summary: string;
  findings: ThreatFinding[];
  meta?: Record<string, string | number | boolean>;
}

export interface ScanReport {
  id: string;
  startedAt: string;
  finishedAt: string;
  engines: EngineResult[];
  securityScore: number;
  readiness: ReleaseReadiness;
  readinessLabel: string;
  readinessHint: string;
  threatCount: number;
  criticalCount: number;
  highCount: number;
  consensus: string;
}

export interface StoreApp {
  id: string;
  slug: string;
  name: string;
  tagline: string;
  description: string;
  kind: AppKind;
  category: string;
  developerName: string;
  developerEmail?: string;
  version: string;
  homepage?: string;
  tags: string[];
  status: AppStatus;
  createdAt: string;
  updatedAt: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  filePath: string;
  sha256: string;
  downloads: number;
  iconHue: number;
  scan?: ScanReport;
}

export interface StoreDatabase {
  apps: StoreApp[];
}

export interface PublishInput {
  name: string;
  tagline: string;
  description: string;
  kind: AppKind;
  category: string;
  developerName: string;
  developerEmail?: string;
  version: string;
  homepage?: string;
  tags: string[];
}
