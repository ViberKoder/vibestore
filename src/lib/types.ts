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
  | "web-static"
  | "secrets"
  | "electron-hardening"
  | "privacy"
  | "device-footprint"
  | "integrity";

export type ScannerVerdict =
  | "clean"
  | "suspicious"
  | "malicious"
  | "error"
  | "skipped";

export type ReleaseReadiness = "ready" | "needs_fixes" | "blocked";

export type ScanEnginePhase = "pending" | "running" | "done";

export interface ThreatFinding {
  id: string;
  scanner: ScannerId;
  severity: ThreatSeverity;
  title: string;
  detail: string;
  /** Plain-language explanation for humans */
  meaning?: string;
  /** Concrete next step for the developer */
  action?: string;
  /** Ready-to-paste prompt for an AI coding agent */
  agentPrompt?: string;
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
    | "performance"
    | "integrity"
    | "other";
}

export interface AppFeature {
  title: string;
  detail?: string;
}

export interface AppScreenshot {
  id: string;
  fileName: string;
  /** Public path served by /api/media/... */
  url: string;
  caption?: string;
  width?: number;
  height?: number;
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

export interface ScanEngineProgress {
  scanner: ScannerId;
  displayName: string;
  phase: ScanEnginePhase;
  verdict?: ScannerVerdict;
  summary?: string;
  startedAt?: string;
  finishedAt?: string;
}

export interface ScanProgress {
  phase: "queued" | "running" | "done" | "error";
  label: string;
  percent: number;
  currentEngine?: ScannerId;
  engines: ScanEngineProgress[];
  error?: string;
  updatedAt: string;
}

/** Independent auditor axes (Vibe Audit). */
export interface AuditPillars {
  safety: number;
  privacy: number;
  hardening: number;
  integrity: number;
  device: number;
}

export interface ScanReport {
  id: string;
  startedAt: string;
  finishedAt: string;
  engines: EngineResult[];
  /** @deprecated prefer pillars + trustScore; kept as overall trust for UI/compat */
  securityScore: number;
  trustScore?: number;
  pillars?: AuditPillars;
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
  /** Product capabilities shown on the store page */
  features: AppFeature[];
  /** UI / product screenshots */
  screenshots: AppScreenshot[];
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
  scanProgress?: ScanProgress;
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
  features?: AppFeature[];
}

/** Soft ceiling for product screenshots at publish time. */
export const MAX_SCREENSHOTS = 8;
export const MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024;
export const MAX_FEATURES = 12;

export const SCAN_ENGINE_ORDER: Array<{
  scanner: ScannerId;
  displayName: string;
}> = [
  // Existing AV / malware stack (must stay)
  { scanner: "clamav", displayName: "ClamAV" },
  { scanner: "clamwin", displayName: "ClamWin (ClamAV DB)" },
  { scanner: "virustotal", displayName: "VirusTotal" },
  { scanner: "vibeguard", displayName: "VibeGuard" },
  { scanner: "entropy", displayName: "Entropy Analyzer" },
  { scanner: "pe-inspector", displayName: "PE Inspector" },
  { scanner: "network-sink", displayName: "Network Sink Scanner" },
  { scanner: "web-static", displayName: "Web Static Auditor" },
  // Vibe Audit Stage A
  { scanner: "secrets", displayName: "Secrets Auditor" },
  { scanner: "electron-hardening", displayName: "Electron Hardening" },
  { scanner: "privacy", displayName: "Privacy Auditor" },
  { scanner: "integrity", displayName: "Integrity Auditor" },
  { scanner: "device-footprint", displayName: "Device Footprint" },
];

export const PILLAR_META: Array<{
  key: keyof AuditPillars;
  title: string;
  subtitle: string;
}> = [
  {
    key: "safety",
    title: "Safety",
    subtitle: "Вирусы, трояны, стиллеры",
  },
  {
    key: "privacy",
    title: "Privacy",
    subtitle: "Трекеры и чувствительные API",
  },
  {
    key: "hardening",
    title: "Hardening",
    subtitle: "Взлом, секреты, Electron",
  },
  {
    key: "integrity",
    title: "Integrity",
    subtitle: "Подпись, подмена, упаковка",
  },
  {
    key: "device",
    title: "Device",
    subtitle: "Тормоза, майнинг, автозапуск",
  },
];

/** Soft ceiling for very large builds (e.g. 200MB installers). */
export const MAX_UPLOAD_BYTES = 512 * 1024 * 1024;
