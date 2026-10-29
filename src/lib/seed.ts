import type { EngineResult, ScanReport, StoreApp, ThreatFinding } from "./types";

function eng(
  partial: Omit<EngineResult, "durationMs" | "findings"> & {
    findings?: ThreatFinding[];
  },
): EngineResult {
  return {
    durationMs: 160,
    findings: [],
    ...partial,
  };
}

function report(
  partial: Omit<ScanReport, "startedAt" | "finishedAt" | "engines"> & {
    engines: EngineResult[];
  },
): ScanReport {
  const now = new Date().toISOString();
  return { startedAt: now, finishedAt: now, ...partial };
}

export function seedApps(): StoreApp[] {
  const now = new Date().toISOString();

  const cleanEngines: EngineResult[] = [
    eng({
      scanner: "clamav",
      displayName: "ClamAV",
      verdict: "clean",
      score: 100,
      summary: "No known signatures.",
    }),
    eng({
      scanner: "clamwin",
      displayName: "ClamWin (ClamAV DB)",
      verdict: "clean",
      score: 98,
      summary: "Windows signatures clean.",
    }),
    eng({
      scanner: "virustotal",
      displayName: "VirusTotal",
      verdict: "clean",
      score: 97,
      summary: "0 / 70 vendors flagged.",
    }),
    eng({
      scanner: "vibeguard",
      displayName: "VibeGuard",
      verdict: "clean",
      score: 100,
      summary: "Proprietary rules: clean.",
    }),
    eng({
      scanner: "entropy",
      displayName: "Entropy Analyzer",
      verdict: "clean",
      score: 95,
      summary: "Entropy 5.42 bits/byte.",
    }),
    eng({
      scanner: "pe-inspector",
      displayName: "PE Inspector",
      verdict: "skipped",
      score: 100,
      summary: "Not a PE target.",
    }),
    eng({
      scanner: "network-sink",
      displayName: "Network Sink Scanner",
      verdict: "clean",
      score: 100,
      summary: "No shady sinks.",
    }),
    eng({
      scanner: "web-static",
      displayName: "Web Static Auditor",
      verdict: "clean",
      score: 96,
      summary: "No common web vuln/bug patterns.",
    }),
  ];

  const cleanScan = report({
    id: "scan_seed_clean",
    securityScore: 97,
    readiness: "ready",
    readinessLabel: "Ready for mass release",
    readinessHint:
      "Engines agree the build looks safe. Keep monitoring updates.",
    consensus: "Clean consensus across antivirus and proprietary engines.",
    threatCount: 0,
    criticalCount: 0,
    highCount: 0,
    engines: cleanEngines,
  });

  const cautionScan = report({
    id: "scan_seed_caution",
    securityScore: 68,
    readiness: "needs_fixes",
    readinessLabel: "Needs fixes before launch",
    readinessHint:
      "Ship only after resolving high/medium findings and re-scanning.",
    consensus: "Mixed signals — treat as pre-release, not production.",
    threatCount: 3,
    criticalCount: 0,
    highCount: 1,
    engines: [
      eng({
        scanner: "clamav",
        displayName: "ClamAV",
        verdict: "clean",
        score: 92,
        summary: "No malware signatures.",
      }),
      eng({
        scanner: "clamwin",
        displayName: "ClamWin (ClamAV DB)",
        verdict: "clean",
        score: 90,
        summary: "Clean.",
      }),
      eng({
        scanner: "virustotal",
        displayName: "VirusTotal",
        verdict: "suspicious",
        score: 72,
        summary: "2 suspicious vendors.",
      }),
      eng({
        scanner: "vibeguard",
        displayName: "VibeGuard",
        verdict: "suspicious",
        score: 60,
        summary: "Packed blobs detected.",
        findings: [
          {
            id: "seed-eval",
            scanner: "vibeguard",
            severity: "medium",
            title: "Heavy Base64 payload blobs",
            detail: "Found 4 large encoded blobs.",
            category: "packed",
          },
        ],
      }),
      eng({
        scanner: "entropy",
        displayName: "Entropy Analyzer",
        verdict: "suspicious",
        score: 55,
        summary: "Entropy 7.71 bits/byte.",
        findings: [
          {
            id: "seed-ent",
            scanner: "entropy",
            severity: "medium",
            title: "High entropy (likely packed/encrypted)",
            detail: "Shannon entropy 7.71/8.",
            category: "packed",
          },
        ],
      }),
      eng({
        scanner: "pe-inspector",
        displayName: "PE Inspector",
        verdict: "suspicious",
        score: 70,
        summary: "Network + credential API mix.",
        findings: [
          {
            id: "seed-pe",
            scanner: "pe-inspector",
            severity: "high",
            title: "Network + credential API mix",
            detail: "Imports: wininet.dll, ws2_32.dll, advapi32.dll",
            category: "network",
          },
        ],
      }),
      eng({
        scanner: "network-sink",
        displayName: "Network Sink Scanner",
        verdict: "clean",
        score: 88,
        summary: "1 URL reviewed.",
      }),
      eng({
        scanner: "web-static",
        displayName: "Web Static Auditor",
        verdict: "skipped",
        score: 100,
        summary: "Not a web artifact.",
      }),
    ],
  });

  const blockedScan = report({
    id: "scan_seed_blocked",
    securityScore: 12,
    readiness: "blocked",
    readinessLabel: "Blocked — do not distribute",
    readinessHint:
      "Critical malware/stealer/trojan indicators. Quarantined from the store.",
    consensus: "Strong malicious consensus — download disabled for users.",
    threatCount: 5,
    criticalCount: 3,
    highCount: 2,
    engines: [
      eng({
        scanner: "clamav",
        displayName: "ClamAV",
        verdict: "malicious",
        score: 0,
        summary: "Stealer signature hit.",
        findings: [
          {
            id: "seed-clam",
            scanner: "clamav",
            severity: "critical",
            title: "ClamAV-like hit: stealer",
            detail: "Heuristic stealer family.",
            category: "stealer",
          },
        ],
      }),
      eng({
        scanner: "clamwin",
        displayName: "ClamWin (ClamAV DB)",
        verdict: "malicious",
        score: 5,
        summary: "Windows stealer signatures.",
      }),
      eng({
        scanner: "virustotal",
        displayName: "VirusTotal",
        verdict: "malicious",
        score: 8,
        summary: "41 / 70 vendors flagged.",
      }),
      eng({
        scanner: "vibeguard",
        displayName: "VibeGuard",
        verdict: "malicious",
        score: 0,
        summary: "Discord webhook + wallet harvest.",
        findings: [
          {
            id: "seed-wh",
            scanner: "vibeguard",
            severity: "critical",
            title: "Discord webhook exfiltration",
            detail: "Proprietary rule matched.",
            category: "stealer",
          },
          {
            id: "seed-wallet",
            scanner: "vibeguard",
            severity: "critical",
            title: "Crypto wallet path harvest",
            detail: "Electrum/Exodus paths referenced.",
            category: "stealer",
          },
        ],
      }),
      eng({
        scanner: "entropy",
        displayName: "Entropy Analyzer",
        verdict: "suspicious",
        score: 50,
        summary: "Entropy 7.85.",
      }),
      eng({
        scanner: "pe-inspector",
        displayName: "PE Inspector",
        verdict: "malicious",
        score: 20,
        summary: "Fake document.exe pattern.",
      }),
      eng({
        scanner: "network-sink",
        displayName: "Network Sink Scanner",
        verdict: "suspicious",
        score: 30,
        summary: "Telegram bot sink.",
      }),
      eng({
        scanner: "web-static",
        displayName: "Web Static Auditor",
        verdict: "skipped",
        score: 100,
        summary: "Not a web artifact.",
      }),
    ],
  });

  return [
    {
      id: "app_pixel_notes",
      slug: "pixel-notes",
      name: "Pixel Notes",
      tagline: "Локальные заметки для вайб-сессий без облака",
      description:
        "Минималистичный блокнот. Хранит всё на диске, без аналитики и без скрытых сетевых вызовов.",
      kind: "desktop",
      category: "Productivity",
      developerName: "Nora Vibe",
      version: "1.2.0",
      homepage: "https://example.com/pixel-notes",
      tags: ["notes", "offline", "electron"],
      status: "published",
      createdAt: now,
      updatedAt: now,
      fileName: "pixel-notes-1.2.0.zip",
      fileSize: 2_450_000,
      mimeType: "application/zip",
      filePath: "",
      sha256: "a".repeat(64),
      downloads: 1284,
      iconHue: 168,
      scan: cleanScan,
    },
    {
      id: "app_ship_radar",
      slug: "ship-radar",
      name: "Ship Radar",
      tagline: "Чеклист готовности релиза для соло-разработчиков",
      description:
        "Веб-утилита: чеклисты и smoke-тесты перед выкладкой. Полезна вайбкодерам перед публичным релизом.",
      kind: "web",
      category: "Developer Tools",
      developerName: "Atlas Labs",
      version: "0.9.4",
      tags: ["release", "checklist", "web"],
      status: "published",
      createdAt: now,
      updatedAt: now,
      fileName: "ship-radar.html",
      fileSize: 84_200,
      mimeType: "text/html",
      filePath: "",
      sha256: "b".repeat(64),
      downloads: 642,
      iconHue: 198,
      scan: cleanScan,
    },
    {
      id: "app_clip_forge",
      slug: "clip-forge",
      name: "ClipForge",
      tagline: "Быстрый .exe-конвертер клипов с GPU-пресетами",
      description:
        "Windows-утилита для нарезки роликов. Сейчас на доработке по результатам скана безопасности.",
      kind: "desktop",
      category: "Media",
      developerName: "Forge Soft",
      version: "0.3.1",
      tags: ["windows", "exe", "video"],
      status: "quarantined",
      createdAt: now,
      updatedAt: now,
      fileName: "ClipForge-setup.exe",
      fileSize: 12_800_000,
      mimeType: "application/vnd.microsoft.portable-executable",
      filePath: "",
      sha256: "c".repeat(64),
      downloads: 89,
      iconHue: 32,
      scan: cautionScan,
    },
    {
      id: "app_free_nitro",
      slug: "free-nitro-helper",
      name: "Free Nitro Helper",
      tagline: "«Бесплатный Nitro» — учебный образец стиллера",
      description:
        "Демонстрационный вредоносный образец. Скачивание заблокировано — так Vibe Store ловит стиллеры.",
      kind: "desktop",
      category: "Security Demo",
      developerName: "Red Team Fixtures",
      version: "0.0.1",
      tags: ["demo", "malware", "blocked"],
      status: "rejected",
      createdAt: now,
      updatedAt: now,
      fileName: "nitro-helper.exe",
      fileSize: 420_000,
      mimeType: "application/vnd.microsoft.portable-executable",
      filePath: "",
      sha256: "d".repeat(64),
      downloads: 0,
      iconHue: 8,
      scan: blockedScan,
    },
  ];
}
