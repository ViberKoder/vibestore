import type { ThreatFinding } from "../types";
import { extractHosts, categorise } from "../scanners/domains";

/**
 * DEX string scan. Class and method names are stored as plain (MUTF-8) strings in
 * the DEX string table, so API use can be spotted by byte search. Presence of an
 * API is evidence of capability, not proof of use; the findings say so.
 */
interface Rule {
  id: string;
  /** Every needle must appear somewhere in the dex files */
  all: string[];
  severity: ThreatFinding["severity"];
  category: ThreatFinding["category"];
  title: string;
  meaning: string;
  action: string;
}

const RULES: Rule[] = [
  {
    id: "dex-runtime-code", all: ["Ldalvik/system/DexClassLoader;"], severity: "high", category: "trojan",
    title: "Loads code at runtime (DexClassLoader)",
    meaning: "Code downloaded or unpacked at runtime is not visible to store review — the classic way to change behaviour after approval.",
    action: "Ship all code in the package, or explain and document the runtime loading.",
  },
  {
    id: "dex-inmemory-loader", all: ["Ldalvik/system/InMemoryDexClassLoader;"], severity: "high", category: "trojan",
    title: "Loads code from memory (InMemoryDexClassLoader)",
    meaning: "Code can be decrypted in memory and never touch the package on disk.",
    action: "Remove dynamic loading or document exactly what is loaded and why.",
  },
  {
    id: "dex-process", all: ["Ljava/lang/Runtime;", "exec"], severity: "medium", category: "trojan",
    title: "Can run shell commands (Runtime.exec)",
    meaning: "Shell access lets the app run arbitrary programs on the device.",
    action: "Remove shell execution unless the product needs it; document it if it does.",
  },
  {
    id: "dex-processbuilder", all: ["Ljava/lang/ProcessBuilder;"], severity: "low", category: "other",
    title: "Starts external processes (ProcessBuilder)",
    meaning: "Process creation is a capability that must have a purpose.",
    action: "Confirm the use is needed.",
  },
  {
    id: "dex-sms", all: ["Landroid/telephony/SmsManager;"], severity: "medium", category: "stealer",
    title: "Sends SMS messages (SmsManager)",
    meaning: "Silent SMS is used for premium-rate fraud and to hijack one-time codes.",
    action: "Send SMS only from an explicit user action, shown on screen.",
  },
  {
    id: "dex-accessibility", all: ["Landroid/accessibilityservice/AccessibilityService;"], severity: "high", category: "stealer",
    title: "Accessibility service API",
    meaning: "Accessibility services can read every screen and perform taps. Banking trojans abuse this to steal codes and money.",
    action: "Use accessibility only for its declared purpose; never read other apps' sensitive screens.",
  },
  {
    id: "dex-device-admin", all: ["Landroid/app/admin/DeviceAdminReceiver;"], severity: "medium", category: "policy",
    title: "Device administrator API",
    meaning: "Device admins can lock the device, wipe it or prevent uninstall.",
    action: "Use device admin only for enterprise management and explain it.",
  },
  {
    id: "dex-screen-capture", all: ["Landroid/media/projection/MediaProjection;"], severity: "high", category: "stealer",
    title: "Screen capture (MediaProjection)",
    meaning: "The app can record everything on screen, including passwords and codes.",
    action: "Capture only with an explicit, visible user action.",
  },
  {
    id: "dex-installer", all: ["Landroid/content/pm/PackageInstaller;"], severity: "medium", category: "trojan",
    title: "Installs packages (PackageInstaller)",
    meaning: "Installing other apps is the second stage of droppers.",
    action: "Install only through the system prompt for the app's own updates, if at all.",
  },
  {
    id: "dex-trustmanager", all: ["Ljavax/net/ssl/X509TrustManager;", "checkServerTrusted"], severity: "medium", category: "vulnerability",
    title: "Custom TLS trust manager",
    meaning: "A hand-written trust manager is the usual reason HTTPS stops protecting traffic (any certificate accepted).",
    action: "Use the default trust store, or verify the custom manager rejects bad certificates.",
  },
  {
    id: "dex-js-bridge", all: ["addJavascriptInterface"], severity: "medium", category: "vulnerability",
    title: "WebView JavaScript bridge (addJavascriptInterface)",
    meaning: "Exposes native methods to any page loaded in the WebView; dangerous when the page is remote.",
    action: "Expose minimal methods and only for trusted, local content.",
  },
  {
    id: "dex-universal-file", all: ["setAllowUniversalAccessFromFileURLs"], severity: "high", category: "vulnerability",
    title: "WebView universal file access enabled",
    meaning: "Local files can be read by any loaded script, a known data-theft route.",
    action: "Disable universal file access.",
  },
  {
    id: "dex-weak-cipher", all: ["Ljavax/crypto/Cipher;", "/ECB/"], severity: "medium", category: "vulnerability",
    title: "ECB cipher mode in use",
    meaning: "ECB leaks patterns in data and is not an acceptable mode for secrets.",
    action: "Use AES-GCM with random nonces.",
  },
  {
    id: "dex-root-check", all: ["/system/xbin/su"], severity: "low", category: "other",
    title: "Checks for root (su binary)",
    meaning: "Root detection is common in banking apps and is not itself malicious.",
    action: "No action required unless the check is used to hide behaviour.",
  },
  {
    id: "dex-packer", all: ["Lcom/bangcle/"], severity: "medium", category: "packed",
    title: "Protected by a commercial packer (Bangcle)",
    meaning: "Packers hide the real code from analysis. Legitimate for copy protection, but it blocks review.",
    action: "Ship unprotected code for review, or accept that this build cannot be fully verified.",
  },
];

const PACKER_CLASSES = [
  "Lcom/ijiami/", "Lcom/qihoo/util/", "Lcom/secneo/", "Lcom/tencent/StubShell/", "Lcom/shell/", "Lcom/baidu/protect/", "Lcom/nqshield/",
];

export interface DexScan {
  findings: ThreatFinding[];
  hosts: Map<string, number>;
  text: string;
}

export function scanDex(dexFiles: Array<{ name: string; bytes: Buffer }>, permissions: string[]): DexScan {
  const findings: ThreatFinding[] = [];
  const blobs = dexFiles.map((d) => d.bytes);
  const has = (needle: string) => blobs.some((b) => b.includes(Buffer.from(needle, "utf8")));

  for (const r of RULES) {
    if (!r.all.every(has)) continue;
    findings.push({ id: r.id, scanner: "apk", severity: r.severity, category: r.category, title: r.title,
      detail: `Found in ${dexFiles.length} dex file(s): ${r.all.join(" + ")}`, meaning: r.meaning, action: r.action });
  }
  const packers = PACKER_CLASSES.filter(has);
  if (packers.length) {
    findings.push({ id: "dex-packer-generic", scanner: "apk", severity: "medium", category: "packed",
      title: "Protected by a commercial packer", detail: `Packer classes: ${packers.join(", ")}`,
      meaning: "Packers hide the real code from analysis.",
      action: "Ship unprotected code for review, or accept that this build cannot be fully verified." });
  }
  // Pairing a risky capability with a permission the user is asked for makes it concrete.
  if (has("Landroid/telephony/SmsManager;") && permissions.includes("android.permission.READ_SMS")) {
    findings.push({ id: "dex-sms-read", scanner: "apk", severity: "high", category: "stealer", title: "Reads and sends SMS",
      detail: "SmsManager is referenced and READ_SMS is requested.", meaning: "Reading and sending SMS together enables OTP theft and fraud.",
      action: "Remove SMS access unless the product's core purpose requires it." });
  }

  const text = Buffer.concat(blobs).toString("latin1");
  const hosts = extractHosts(text);
  return { findings, hosts, text };
}

/** Hosts shipped in the code, grouped by risk (same categories as the static auditor). */
export function hostFindings(hosts: Map<string, number>): ThreatFinding[] {
  const out: ThreatFinding[] = [];
  const byCat: Record<string, string[]> = {};
  for (const h of hosts.keys()) (byCat[categorise(h)] ??= []).push(h);
  if (byCat.c2?.length) {
    out.push({ id: "apk-c2-hosts", scanner: "apk", severity: "high", category: "stealer",
      title: `Exfiltration-style endpoints (${byCat.c2.length})`, detail: byCat.c2.slice(0, 8).join(", "),
      meaning: "Chat-bot, webhook, paste or tunnel endpoints are how stealers send data out.",
      action: "Remove endpoints the product does not need." });
  }
  if (byCat.ads?.length) {
    out.push({ id: "apk-ads", scanner: "apk", severity: "low", category: "adware",
      title: `Ad networks (${byCat.ads.length})`, detail: byCat.ads.slice(0, 8).join(", "),
      meaning: "Ad SDKs track users and can show unwanted content.", action: "Disclose the ad networks in the store listing." });
  }
  if (byCat.analytics?.length) {
    out.push({ id: "apk-analytics", scanner: "apk", severity: "low", category: "policy",
      title: `Analytics / tracking (${byCat.analytics.length})`, detail: byCat.analytics.slice(0, 8).join(", "),
      meaning: "Analytics record user behaviour.", action: "Disclose analytics vendors and offer an opt-out." });
  }
  return out;
}
