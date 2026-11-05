import path from "path";
import type { EngineResult, ThreatFinding } from "../types";
import {
  collectAsciiStrings,
  extractSearchText,
  looksLikeElectron,
} from "./extract";
import { inspectPe } from "./pe";
import { sampleEntropy } from "./entropy";

const SECRET_PATTERNS: Array<{
  id: string;
  title: string;
  pattern: RegExp;
  severity: ThreatFinding["severity"];
}> = [
  {
    id: "aws-key",
    title: "Possible AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
  },
  {
    id: "github-pat",
    title: "Possible GitHub token",
    pattern: /gh[pousr]_[A-Za-z0-9_]{20,}/g,
    severity: "critical",
  },
  {
    id: "slack-token",
    title: "Possible Slack token",
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    severity: "high",
  },
  {
    id: "generic-api-key",
    title: "Hardcoded API key / secret",
    pattern:
      /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"']{12,}["']/gi,
    severity: "high",
  },
  {
    id: "private-key",
    title: "Private key in the binary",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
  },
  {
    id: "jwt-secret",
    title: "Looks like a JWT / bearer secret",
    pattern: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: "medium",
  },
];

const TRACKER_DOMAINS: Array<{ host: string; label: string; severity: ThreatFinding["severity"] }> =
  [
    { host: "google-analytics.com", label: "Google Analytics", severity: "low" },
    { host: "googletagmanager.com", label: "Google Tag Manager", severity: "low" },
    { host: "facebook.com/tr", label: "Facebook Pixel", severity: "medium" },
    { host: "amplitude.com", label: "Amplitude", severity: "low" },
    { host: "mixpanel.com", label: "Mixpanel", severity: "low" },
    { host: "sentry.io", label: "Sentry", severity: "low" },
    { host: "hotjar.com", label: "Hotjar", severity: "medium" },
    { host: "fullstory.com", label: "FullStory", severity: "medium" },
    { host: "segment.io", label: "Segment", severity: "low" },
    { host: "segment.com", label: "Segment", severity: "low" },
    { host: "appsflyer.com", label: "AppsFlyer", severity: "medium" },
    { host: "adjust.com", label: "Adjust", severity: "medium" },
    { host: "clarity.ms", label: "Microsoft Clarity", severity: "medium" },
    { host: "doubleclick.net", label: "DoubleClick ads", severity: "medium" },
  ];

function scoreFromFindings(findings: ThreatFinding[]): number {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  return Math.max(0, 100 - critical * 35 - high * 18 - medium * 8 - low * 3);
}

function verdictFromFindings(findings: ThreatFinding[]): EngineResult["verdict"] {
  if (findings.some((f) => f.severity === "critical")) return "malicious";
  if (findings.some((f) => f.severity === "high")) return "suspicious";
  if (findings.length) return "suspicious";
  return "clean";
}

/** Hardcoded secrets / credentials auditor */
export async function runSecretsAuditor(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const text = extractSearchText(buf);
  const findings: ThreatFinding[] = [];

  for (const sig of SECRET_PATTERNS) {
    const matches = text.match(sig.pattern);
    if (!matches?.length) continue;
    const sample = matches[0].slice(0, 24);
    findings.push({
      id: `sec-${sig.id}`,
      scanner: "secrets",
      severity: sig.severity,
      title: sig.title,
      detail: `Matches found: ${matches.length}. Sample (trimmed): ${sample}…`,
      category: "vulnerability",
      meaning:
        "Anyone can extract secrets from a client build — a direct risk of backend/account compromise.",
      action:
        "Remove keys from the binary. Issue tokens from the server and rotate secrets that have already leaked.",
    });
  }

  if (/password\s*[:=]\s*["'][^"']{4,}["']/i.test(text)) {
    findings.push({
      id: "sec-password-literal",
      scanner: "secrets",
      severity: "high",
      title: "Literal password in the build",
      detail: "A string like password=… was found inside the file.",
      category: "vulnerability",
      meaning: "Passwords in the client are almost always compromised.",
      action: "Remove hardcoded passwords; store them only on the server.",
    });
  }

  return {
    scanner: "secrets",
    displayName: "Secrets Auditor",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? `No secrets found in the strings of ${fileName}.`
        : `Potential secrets found: ${findings.length}.`,
    findings,
    meta: { pillar: "hardening" },
  };
}

/** Electron / Chromium hardening checks (static string heuristics). */
export async function runElectronHardening(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const text = extractSearchText(buf, 4_000_000);
  const findings: ThreatFinding[] = [];
  const electron = looksLikeElectron(text);
  const looksJsBundle =
    /\.(js|html|asar)$/i.test(fileName) || /nodeIntegration|BrowserWindow/i.test(text);

  if (!electron && !looksJsBundle && !/\.(exe|dmg|appimage|zip)$/i.test(fileName)) {
    return {
      scanner: "electron-hardening",
      displayName: "Electron Hardening",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "Does not look like an Electron/Chromium target — skipped.",
      findings: [],
      meta: { skipped: true, pillar: "hardening" },
    };
  }

  if (!electron && /\.(exe|dmg)$/i.test(fileName)) {
    // Still run light checks; mark as limited
  }

  if (/nodeIntegration["']?\s*:\s*true/i.test(text) || /nodeIntegration:\s*!0/i.test(text)) {
    findings.push({
      id: "el-node-integration",
      scanner: "electron-hardening",
      severity: "critical",
      title: "nodeIntegration: true",
      detail: "The renderer may get Node API access — XSS becomes RCE.",
      category: "vulnerability",
      meaning:
        "Any XSS in the UI can run arbitrary code on the user's machine.",
      action: "Turn off nodeIntegration and use contextBridge + preload.",
    });
  }

  if (/contextIsolation["']?\s*:\s*false/i.test(text) || /contextIsolation:\s*!1/i.test(text)) {
    findings.push({
      id: "el-no-isolation",
      scanner: "electron-hardening",
      severity: "high",
      title: "contextIsolation: false",
      detail: "Context isolation is disabled — a dangerous Electron default from past years.",
      category: "vulnerability",
      meaning: "The page may reach into privileged preload/API.",
      action: "Enable contextIsolation: true in every BrowserWindow.",
    });
  }

  if (/webSecurity["']?\s*:\s*false/i.test(text)) {
    findings.push({
      id: "el-websecurity-off",
      scanner: "electron-hardening",
      severity: "high",
      title: "webSecurity: false",
      detail: "Chromium web security is disabled (CORS/SOP weakened).",
      category: "vulnerability",
      meaning: "Makes XSS and loading foreign content easier.",
      action: "Keep webSecurity: true; do not disable it unless absolutely necessary.",
    });
  }

  if (/allowRunningInsecureContent["']?\s*:\s*true/i.test(text)) {
    findings.push({
      id: "el-insecure-content",
      scanner: "electron-hardening",
      severity: "medium",
      title: "allowRunningInsecureContent",
      detail: "Mixed content is allowed (HTTP inside HTTPS/the app).",
      category: "vulnerability",
      meaning: "Traffic can be tampered with on the local network.",
      action: "Turn off insecure content; use HTTPS only.",
    });
  }

  const electronVer = text.match(/Electron\/(\d+\.\d+\.\d+)/i)?.[1];
  if (electronVer) {
    const major = Number(electronVer.split(".")[0]);
    if (major > 0 && major < 22) {
      findings.push({
        id: "el-old-runtime",
        scanner: "electron-hardening",
        severity: "high",
        title: `Outdated Electron ${electronVer}`,
        detail: "Old Chromium/Electron often contains public CVEs.",
        category: "vulnerability",
        meaning: "Known runtime holes are a ready-made attack vector for the app.",
        action: "Update Electron to a supported LTS and rebuild.",
      });
    }
  }

  if (/openDevTools\(|devTools:\s*true/i.test(text) && /production|app\.isPackaged/i.test(text)) {
    findings.push({
      id: "el-devtools-prod",
      scanner: "electron-hardening",
      severity: "low",
      title: "DevTools may be reachable in release builds",
      detail: "Signs of openDevTools/devTools:true next to production code.",
      category: "policy",
      meaning: "Makes reverse engineering and token theft from the renderer easier.",
      action: "Disable DevTools in production builds.",
    });
  }

  const score = scoreFromFindings(findings);
  return {
    scanner: "electron-hardening",
    displayName: "Electron Hardening",
    verdict: electron || findings.length ? verdictFromFindings(findings) : "skipped",
    score: electron || findings.length ? score : 100,
    durationMs: Date.now() - started,
    summary: electron
      ? findings.length
        ? `Electron build: ${findings.length} hardening issues.`
        : `Electron detected${electronVer ? ` (${electronVer})` : ""} — no dangerous flags visible.`
      : findings.length
        ? `Electron-like flags found: ${findings.length}.`
        : "No explicit Electron markers — limited check.",
    findings,
    meta: {
      pillar: "hardening",
      electronDetected: electron,
      electronVersion: electronVer ?? "unknown",
    },
  };
}

/** Privacy / trackers / analytics domain auditor */
export async function runPrivacyAuditor(buf: Buffer): Promise<EngineResult> {
  const started = Date.now();
  const text = extractSearchText(buf);
  const findings: ThreatFinding[] = [];
  const hits: string[] = [];

  for (const t of TRACKER_DOMAINS) {
    if (text.toLowerCase().includes(t.host.toLowerCase())) {
      hits.push(t.label);
      findings.push({
        id: `priv-${t.host.replace(/\W+/g, "-")}`,
        scanner: "privacy",
        severity: t.severity,
        title: `Tracker / analytics: ${t.label}`,
        detail: `Host ${t.host} appears in the build`,
        category: "policy",
        meaning:
          "Analytics and pixels collect user behavior. For a vibe-coded product this is a trust issue and sometimes a GDPR issue.",
        action:
          "Document the trackers on the app page, offer an opt-out or remove them.",
      });
    }
  }

  if (/navigator\.geolocation|getCurrentPosition/i.test(text)) {
    findings.push({
      id: "priv-geo",
      scanner: "privacy",
      severity: "medium",
      title: "Location request",
      detail: "The code uses navigator.geolocation / getCurrentPosition.",
      category: "policy",
      meaning: "Location is sensitive data; without a clear benefit it is an unnecessary risk.",
      action: "Request location only on the user's action and explain why.",
    });
  }

  if (/mediaDevices\.getUserMedia|getUserMedia\s*\(/i.test(text)) {
    findings.push({
      id: "priv-media",
      scanner: "privacy",
      severity: "medium",
      title: "Camera / microphone access",
      detail: "getUserMedia detected.",
      category: "policy",
      meaning: "Camera/microphone — a high privacy level.",
      action: "Ask for permission explicitly and only when the feature is actually needed.",
    });
  }

  // clipboard / screenshot-ish
  if (/clipboard\.read|readText\(|desktopCapturer/i.test(text)) {
    findings.push({
      id: "priv-clipboard",
      scanner: "privacy",
      severity: "high",
      title: "Clipboard reading / screen capture",
      detail: "Clipboard/desktopCapturer API used in the build.",
      category: "stealer",
      meaning: "This is how stealers and silent surveillance often look.",
      action: "Make sure this is a declared feature; otherwise remove it.",
    });
  }

  return {
    scanner: "privacy",
    displayName: "Privacy Auditor",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? "No obvious trackers or sensitive privacy APIs."
        : `Privacy: ${findings.length} signal(s)${hits.length ? ` · ${[...new Set(hits)].slice(0, 4).join(", ")}` : ""}.`,
    findings,
    meta: { pillar: "privacy", trackers: hits.join(",") || "none" },
  };
}

/** Device footprint / performance risk heuristics */
export async function runDeviceFootprint(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const findings: ThreatFinding[] = [];
  const sizeMb = buf.length / (1024 * 1024);
  const text = extractSearchText(buf, 2_000_000);
  const entropy = sampleEntropy(buf);

  if (sizeMb >= 250) {
    findings.push({
      id: "fp-huge",
      scanner: "device-footprint",
      severity: "medium",
      title: `Very large distribution (${sizeMb.toFixed(0)} MB)`,
      detail: "Heavy installers take longer to download and use disk space.",
      category: "performance",
      meaning: "Poor UX on weak PCs and mobile internet; updates often take forever.",
      action: "Compress assets, remove unnecessary runtimes, split into optional components.",
    });
  } else if (sizeMb >= 120) {
    findings.push({
      id: "fp-large",
      scanner: "device-footprint",
      severity: "low",
      title: `Large distribution (${sizeMb.toFixed(0)} MB)`,
      detail: "The size is noticeable for a desktop utility.",
      category: "performance",
      meaning: "Not a bug, but users on HDDs or weak Wi-Fi will notice.",
      action: "Check whether the full Chromium/Electron stack is needed.",
    });
  }

  if (/stratum\+|xmrig|coinhive|cryptonight|ethash|NiceHash/i.test(text)) {
    findings.push({
      id: "fp-miner",
      scanner: "device-footprint",
      severity: "critical",
      title: "Signs of a crypto miner",
      detail: "Strings contain mining/pool indicators.",
      category: "virus",
      meaning: "Mining eats CPU/GPU and battery — direct harm to the device.",
      action: "Remove the miner. Such builds are blocked by the store.",
    });
  }

  if (/SetWindowsHookEx|RegisterHotKey|powercfg|HIGH_PRIORITY_CLASS/i.test(text)) {
    findings.push({
      id: "fp-hooks-priority",
      scanner: "device-footprint",
      severity: "medium",
      title: "System hooks / high priority",
      detail: "Keyboard hook or process priority elevation APIs are present.",
      category: "performance",
      meaning: "It may slow the system down or intercept input.",
      action: "Keep only if this is a declared feature (macros, etc.).",
    });
  }

  if (/while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/i.test(text) && /setInterval\s*\(\s*[^,]+,\s*[0-5]\s*\)/i.test(text)) {
    findings.push({
      id: "fp-tight-loop",
      scanner: "device-footprint",
      severity: "low",
      title: "Signs of tight loops / frequent timers",
      detail: "JS/strings contain a tight loop or setInterval with a very small delay.",
      category: "performance",
      meaning: "Background loops keep the CPU warm even when idle.",
      action: "Reduce polling frequency; use an event-driven approach.",
    });
  }

  if (entropy >= 7.9 && sizeMb >= 50) {
    findings.push({
      id: "fp-packed-heavy",
      scanner: "device-footprint",
      severity: "low",
      title: "Densely packed large binary",
      detail: `Entropy ${entropy.toFixed(2)} at a size of ${sizeMb.toFixed(0)} MB.`,
      category: "performance",
      meaning: "Unpacking on install/launch spikes CPU and disk.",
      action: "Normal for an installer; make sure there is no extra double-pack.",
    });
  }

  // Autostart hints
  if (/CurrentVersion\\\\Run|LaunchAgents|launchd|schtasks|StartupApproved/i.test(text)) {
    findings.push({
      id: "fp-autostart",
      scanner: "device-footprint",
      severity: "medium",
      title: "Autostart at system startup",
      detail: "Registry/LaunchAgents/schtasks strings for autostart are present.",
      category: "policy",
      meaning: "The app will run in the background and use resources without an explicit start.",
      action: "Make autostart opt-in and explain it to the user.",
    });
  }

  void fileName;
  return {
    scanner: "device-footprint",
    displayName: "Device Footprint",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? `Footprint OK · ${sizeMb.toFixed(1)} MB.`
        : `Device impact: ${findings.length} signal(s) · ${sizeMb.toFixed(0)} MB.`,
    findings,
    meta: {
      pillar: "device",
      sizeMb: Number(sizeMb.toFixed(2)),
      entropy: Number(entropy.toFixed(3)),
    },
  };
}

/** Integrity / authenticity heuristics (signature presence, PE authenticity cues). */
export async function runIntegrityAuditor(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const findings: ThreatFinding[] = [];
  const pe = inspectPe(buf);
  const text = extractSearchText(buf, 2_500_000);
  const strings = collectAsciiStrings(buf, { minLen: 8, maxStrings: 2500 });
  const ext = path.extname(fileName).toLowerCase();

  if (/\.(exe|dll|msi|sys)$/i.test(ext) || pe.isPe) {
    // Authenticode directory often referenced; heuristic: look for signature-related strings
    const hasSigCue =
      /SignerSign|WinVerifyTrust|digicert|sectigo|globalsign|verisign|Certum|Authenticode|signtool/i.test(
        text,
      ) || strings.some((s) => /DigiCert|Sectigo|GlobalSign|Certum/i.test(s));

    // PE attribute certificate table at data directory index 4 — rough parse
    let hasCertTable = false;
    if (pe.isPe && buf.length > 0x100) {
      try {
        const peOffset = buf.readUInt32LE(0x3c);
        const optMagic = buf.readUInt16LE(peOffset + 24);
        const ddOffset =
          optMagic === 0x20b
            ? peOffset + 24 + 112 // PE32+
            : peOffset + 24 + 96; // PE32
        if (ddOffset + 40 < buf.length) {
          const certVa = buf.readUInt32LE(ddOffset + 32);
          const certSize = buf.readUInt32LE(ddOffset + 36);
          hasCertTable = certVa > 0 && certSize > 0;
        }
      } catch {
        /* ignore parse errors */
      }
    }

    if (!hasCertTable && !hasSigCue) {
      findings.push({
        id: "int-unsigned",
        scanner: "integrity",
        severity: "medium",
        title: "No signs of an Authenticode signature",
        detail: "PE has no obvious certificate table / signer metadata.",
        category: "integrity",
        meaning:
          "Windows SmartScreen warns about unsigned .exe files, and the file is easier to swap on the delivery path.",
        action: "Sign the build with a code signing certificate before a mass release.",
      });
    } else if (hasCertTable) {
      // positive — no finding
    }

    if (/\.(pdf|jpg|png|txt|docx)\.exe$/i.test(fileName)) {
      findings.push({
        id: "int-double-ext",
        scanner: "integrity",
        severity: "critical",
        title: "Double extension (document disguise)",
        detail: `The file name ${fileName} disguises an executable as a document.`,
        category: "trojan",
        meaning: "A classic social engineering trick.",
        action: "Rename it honestly (Setup.exe) — otherwise the store will block it.",
      });
    }
  }

  // Source map / debug leftovers
  if (/\.map"|\.pdb|DEBUG_MODE|localhost:\d{2,5}/i.test(text) && /production|app\.asar/i.test(text)) {
    findings.push({
      id: "int-debug-leftovers",
      scanner: "integrity",
      severity: "low",
      title: "Debug artifacts in the release",
      detail: "Source maps / pdb files / localhost debug strings are present.",
      category: "integrity",
      meaning: "Makes reverse engineering easier and points to a raw production build.",
      action: "Strip source maps/pdb from production and close debug endpoints.",
    });
  }

  if (!pe.isPe && !/\.(exe|dll|msi)$/i.test(ext)) {
    if (findings.length === 0) {
      return {
        scanner: "integrity",
        displayName: "Integrity Auditor",
        verdict: "skipped",
        score: 100,
        durationMs: Date.now() - started,
        summary: "Not a Windows PE — signature check skipped.",
        findings: [],
        meta: { skipped: true, pillar: "integrity" },
      };
    }
  }

  return {
    scanner: "integrity",
    displayName: "Integrity Auditor",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? "Integrity: no obvious signature or disguise problems."
        : `Integrity: ${findings.length} finding(s).`,
    findings,
    meta: { pillar: "integrity", isPe: pe.isPe },
  };
}
