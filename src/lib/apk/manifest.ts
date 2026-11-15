import type { ThreatFinding } from "../types";
import { boolAttr, intAttr, type AxmlElement } from "./axml";

export interface ManifestFacts {
  packageName?: string;
  versionName?: string;
  versionCode?: number;
  minSdk?: number;
  targetSdk?: number;
  debuggable?: boolean;
  allowBackup?: boolean;
  cleartext?: boolean;
  testOnly?: boolean;
  permissions: string[];
  components: Array<{ kind: string; name: string; exported: boolean; permission?: string; grantUri?: boolean }>;
}

/** Target API the store asks for. Override with APK_MIN_TARGET_SDK. */
export const MIN_TARGET_SDK = Number(process.env.APK_MIN_TARGET_SDK ?? 35);
const COMPONENTS = new Set(["activity", "activity-alias", "service", "receiver", "provider"]);

export function factsFromManifest(els: AxmlElement[]): ManifestFacts {
  const facts: ManifestFacts = { permissions: [], components: [] };
  // Track the open component so an intent-filter can be attributed to it.
  let openComponent: (ManifestFacts["components"][number] & { explicit?: boolean }) | null = null;

  for (const el of els) {
    const a = el.attrs;
    if (el.tag === "manifest") {
      facts.packageName = a.package?.str;
      facts.versionName = a.versionName?.str;
      facts.versionCode = intAttr(a.versionCode);
    } else if (el.tag === "uses-sdk") {
      facts.minSdk = intAttr(a.minSdkVersion);
      facts.targetSdk = intAttr(a.targetSdkVersion);
    } else if (el.tag === "uses-permission" || el.tag === "uses-permission-sdk-23") {
      const name = a.name?.str;
      if (name) facts.permissions.push(name);
    } else if (el.tag === "application") {
      facts.debuggable = boolAttr(a.debuggable);
      facts.allowBackup = boolAttr(a.allowBackup);
      facts.cleartext = boolAttr(a.usesCleartextTraffic);
      facts.testOnly = boolAttr(a.testOnly);
    } else if (COMPONENTS.has(el.tag)) {
      const exportedAttr = boolAttr(a.exported);
      openComponent = {
        kind: el.tag,
        name: a.name?.str ?? "(unnamed)",
        exported: exportedAttr ?? false,
        permission: a.permission?.str,
        grantUri: boolAttr(a.grantUriPermissions),
        explicit: exportedAttr !== undefined,
      };
      facts.components.push(openComponent);
    } else if (el.tag === "intent-filter" && openComponent) {
      // Without an explicit android:exported, an intent-filter makes the component exported.
      if (!openComponent.explicit) openComponent.exported = true;
    }
  }
  return facts;
}

const DANGEROUS: Record<string, { label: string; sev: ThreatFinding["severity"] }> = {
  "android.permission.READ_SMS": { label: "read SMS (one-time codes, banking messages)", sev: "high" },
  "android.permission.RECEIVE_SMS": { label: "receive SMS", sev: "high" },
  "android.permission.SEND_SMS": { label: "send SMS (premium-SMS fraud pattern)", sev: "high" },
  "android.permission.READ_CALL_LOG": { label: "read call log", sev: "medium" },
  "android.permission.PROCESS_OUTGOING_CALLS": { label: "intercept outgoing calls", sev: "high" },
  "android.permission.READ_CONTACTS": { label: "read contacts", sev: "medium" },
  "android.permission.RECORD_AUDIO": { label: "record audio", sev: "medium" },
  "android.permission.CAMERA": { label: "use the camera", sev: "low" },
  "android.permission.ACCESS_FINE_LOCATION": { label: "precise location", sev: "medium" },
  "android.permission.ACCESS_BACKGROUND_LOCATION": { label: "location in the background", sev: "high" },
  "android.permission.SYSTEM_ALERT_WINDOW": { label: "draw over other apps (overlay / phishing)", sev: "high" },
  "android.permission.BIND_ACCESSIBILITY_SERVICE": { label: "accessibility service (read screens, tap for the user)", sev: "high" },
  "android.permission.REQUEST_INSTALL_PACKAGES": { label: "install other apps", sev: "high" },
  "android.permission.BIND_DEVICE_ADMIN": { label: "device administrator", sev: "high" },
  "android.permission.MANAGE_EXTERNAL_STORAGE": { label: "all files on storage", sev: "high" },
  "android.permission.READ_EXTERNAL_STORAGE": { label: "read shared storage", sev: "low" },
  "android.permission.QUERY_ALL_PACKAGES": { label: "list all installed apps", sev: "medium" },
  "android.permission.RECEIVE_BOOT_COMPLETED": { label: "start at boot (autostart)", sev: "low" },
  "android.permission.READ_PHONE_STATE": { label: "phone identity", sev: "medium" },
};

const NETWORK = "android.permission.INTERNET";

/** Well-known application ids. A new app claiming one of these is an impersonation risk. */
const BRAND_PACKAGES = [
  "com.whatsapp", "org.telegram.messenger", "com.google.android.gm", "com.google.android.youtube",
  "com.facebook.katana", "com.instagram.android", "com.snapchat.android", "com.paypal.android.p2pmobile",
  "com.binance.dev", "com.coinbase.android", "com.revolut.revolut", "ru.sberbankmobile", "ru.tinkoff.tinkoffbank",
  "com.bankofamerica", "com.chase.sig.android", "com.wells_fargo.mobile",
];

export function manifestFindings(f: ManifestFacts): ThreatFinding[] {
  const out: ThreatFinding[] = [];
  const add = (id: string, severity: ThreatFinding["severity"], category: ThreatFinding["category"], title: string, detail: string, meaning: string, action: string) =>
    out.push({ id, scanner: "apk", severity, category, title, detail, meaning, action });

  if (f.debuggable) {
    add("apk-debuggable", "high", "vulnerability", "Debuggable build (android:debuggable=\"true\")",
      "Anyone with USB debugging can attach to the process, read memory and data.",
      "Release builds must never be debuggable.", "Remove android:debuggable or build with release settings.");
  }
  if (f.testOnly) {
    add("apk-testonly", "high", "policy", "Test-only build (android:testOnly=\"true\")",
      "Android refuses to install test-only builds on normal devices unless forced.",
      "A test build is not a product release.", "Build a release variant.");
  }
  if (f.cleartext) {
    add("apk-cleartext", "medium", "vulnerability", "Cleartext HTTP traffic allowed",
      "usesCleartextTraffic=\"true\" lets the app talk over unencrypted HTTP.",
      "Credentials and data can be read or modified on public Wi-Fi.", "Use HTTPS only; keep cleartext for debug builds.");
  }
  if (f.allowBackup === true) {
    add("apk-backup", "low", "vulnerability", "App data can be backed up (allowBackup=true)",
      "Local data (tokens, databases) can be extracted through adb backup.",
      "Sensitive apps should opt out of backups.", "Set android:allowBackup=\"false\" or restrict data with backup rules.");
  }
  if (f.minSdk !== undefined && f.minSdk < 23) {
    add("apk-old-min-sdk", "low", "vulnerability", `Supports Android ${f.minSdk} and older`,
      `minSdkVersion ${f.minSdk}: old systems miss runtime permission prompts and security fixes.`,
      "Runtime permission model arrived in Android 6.", "Raise minSdkVersion where the product allows.");
  }
  if (f.targetSdk !== undefined && f.targetSdk < MIN_TARGET_SDK) {
    add("apk-old-target-sdk", f.targetSdk < 28 ? "high" : "medium", "policy", `Targets Android API ${f.targetSdk}`,
      `targetSdkVersion ${f.targetSdk} is below ${MIN_TARGET_SDK}, the level the store asks for. Old targets disable newer protections.`,
      "Old target levels keep legacy behaviour (cleartext, implicit exports, storage access).",
      `Retarget API ${MIN_TARGET_SDK} and test. (Threshold set by APK_MIN_TARGET_SDK.)`);
  }
  if (f.targetSdk === undefined) {
    add("apk-no-target-sdk", "medium", "policy", "No targetSdkVersion declared",
      "Without a target the system assumes the oldest behaviour.", "Declared targets are required for modern installs.", "Declare uses-sdk targetSdkVersion.");
  }

  const perms = [...new Set(f.permissions)];
  const risky = perms.filter((p) => DANGEROUS[p]);
  for (const p of risky) {
    const d = DANGEROUS[p];
    add(`apk-perm-${p.split(".").pop()}`, d.sev, "policy", `Requests ${p.split(".").pop()}`,
      `The app asks to ${d.label}.`, "Each sensitive permission widens what the app can do with a user's data.",
      "Request only what the feature needs; explain it to the user before the prompt.");
  }
  // Combinations are where data leaves a device: sensitive access plus network.
  if (perms.includes(NETWORK)) {
    const combos: Array<[string[], string, ThreatFinding["severity"]]> = [
      [["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"], "SMS access with network access", "high"],
      [["android.permission.READ_CONTACTS"], "contacts with network access", "medium"],
      [["android.permission.RECORD_AUDIO"], "microphone with network access", "medium"],
      [["android.permission.ACCESS_BACKGROUND_LOCATION"], "background location with network access", "medium"],
      [["android.permission.READ_CALL_LOG"], "call log with network access", "high"],
    ];
    for (const [needs, label, sev] of combos) {
      if (needs.some((p) => perms.includes(p))) {
        add(`apk-combo-${label.replace(/\W+/g, "-")}`, sev, "stealer", `Possible data exfiltration: ${label}`,
          `The app can read sensitive data and also reach the network.`,
          "Sensitive data plus network access is the core of stealer behaviour; intent must be explained.",
          "Justify each sensitive permission with a user-visible feature, or remove it.");
      }
    }
  }
  if (perms.includes("android.permission.SYSTEM_ALERT_WINDOW") && perms.includes("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
    add("apk-combo-overlay-a11y", "high", "stealer", "Overlay plus accessibility service",
      "Drawing over other apps while reading their screens is the pattern of banking trojans.",
      "This combination enables screen-reading phishing overlays.", "Remove one of the two capabilities.");
  }
  if (perms.length > 40) {
    add("apk-many-permissions", "low", "policy", `${perms.length} permissions requested`,
      "Large permission sets are hard to justify.", "Every extra permission is more to explain and more to misuse.", "Remove unused permissions.");
  }

  for (const c of f.components) {
    if (c.exported && !c.permission && c.kind === "provider") {
      add(`apk-exported-provider-${c.name}`, "high", "vulnerability", `Exported content provider: ${c.name}`,
        "Any installed app can query or modify its data without a permission.",
        "Exported providers without permission are a common data leak.", "Set exported=\"false\" or require a signature permission.");
    } else if (c.exported && !c.permission && (c.kind === "receiver" || c.kind === "service")) {
      add(`apk-exported-${c.kind}-${c.name}`, "medium", "vulnerability", `Exported ${c.kind} without permission: ${c.name}`,
        "Other apps can start this component.", "Unprotected exported components can be abused by other installed apps.",
        "Set exported=\"false\" or protect it with a permission.");
    }
    if (c.kind === "provider" && c.grantUri) {
      add(`apk-grant-uri-${c.name}`, "medium", "vulnerability", `Grants URI permissions: ${c.name}`,
        "Provider can hand out access to individual files to other apps.", "Broad URI grants widen the exposure of stored files.",
        "Grant only the paths actually shared.");
    }
  }

  const pkg = f.packageName ?? "";
  const brand = BRAND_PACKAGES.find((b) => pkg === b || pkg.startsWith(`${b}.`));
  if (brand) {
    add("apk-impersonation", "medium", "stealer", `Uses the package name of a well-known app (${brand})`,
      `Package "${pkg}" belongs to a popular service. Fake apps with famous names are a frequent scam.`,
      "Users can confuse a clone with the real product.", "Use your own package name unless you are the publisher of " + brand + ".");
  }
  return out;
}
