import type { EngineResult, ThreatFinding } from "../types";
import { inspectZip, type ArchiveEntry } from "../security/archive";
import { readZipEntry } from "../security/zip-read";
import { sniffType } from "../security/filetype";
import { parseAxml } from "../apk/axml";
import { factsFromManifest, manifestFindings, MIN_TARGET_SDK } from "../apk/manifest";
import { signingFacts } from "../apk/signing";
import { scanDex, hostFindings } from "../apk/dex";
import { runSecretsAuditor } from "./audit";

/**
 * Android package inspector. Works on APK and AAB (Android App Bundle) without
 * installing anything: binary manifest, signing schemes, DEX strings, native
 * libraries and payloads hidden in assets.
 */

const MAX_MANIFEST = 8 * 1024 * 1024;
const MAX_DEX = 96 * 1024 * 1024;
const MAX_ASSET = 16 * 1024 * 1024;
const PACKED_LIBS = /(libjiagu|libshell|libsecexe|libDexHelper|libprotect|libbangcle|libnqshield|libtup|libshella|libexecmain)/i;

export async function runApkEngine(buf: Buffer, fileName: string): Promise<EngineResult> {
  const started = Date.now();
  const skip = (summary: string): EngineResult => ({
    scanner: "apk", displayName: "Android package (APK/AAB)", verdict: "skipped", score: 100,
    durationMs: Date.now() - started, summary, findings: [], meta: {},
  });

  const z = inspectZip(buf);
  if (z.format !== "zip") return skip("Not an Android package.");
  const manifestEntry: ArchiveEntry | undefined = z.entries.find(
    (e) => e.name === "AndroidManifest.xml" || e.name === "base/manifest/AndroidManifest.xml",
  );
  if (!manifestEntry) return skip("No AndroidManifest.xml: not an Android package.");
  const isAab = manifestEntry.name.startsWith("base/");
  const findings: ThreatFinding[] = [];

  const mBytes = readZipEntry(buf, manifestEntry, MAX_MANIFEST);
  const els = mBytes ? parseAxml(mBytes) : null;
  if (!els) {
    return {
      scanner: "apk", displayName: "Android package (APK/AAB)", verdict: "suspicious", score: 30,
      durationMs: Date.now() - started,
      summary: "AndroidManifest.xml could not be decoded — the package cannot be verified.",
      findings: [{ id: "apk-manifest-unreadable", scanner: "apk", severity: "high", category: "policy",
        title: "Manifest could not be decoded", detail: "The binary AndroidManifest.xml is malformed or unsupported.",
        meaning: "Malformed manifests are used to confuse analysis tools and some installers.",
        action: "Rebuild the package with a standard toolchain." }],
      meta: {},
    };
  }
  const facts = factsFromManifest(els);
  findings.push(...manifestFindings(facts));

  // Signing (APK only; an AAB is signed when it is turned into an APK by Google Play).
  const v1Entries = z.entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  const v1Files = v1Entries.flatMap((e) => {
    const b = readZipEntry(buf, e, 1024 * 1024);
    return b ? [{ name: e.name, bytes: b }] : [];
  });
  const sig = isAab ? null : signingFacts(buf, v1Files);
  if (sig) {
    if (!sig.v1 && !sig.v2 && !sig.v3) {
      findings.push({ id: "apk-unsigned", scanner: "apk", severity: "high", category: "policy", title: "APK is unsigned",
        detail: "No v1 (JAR) or v2/v3 (APK Signature Scheme) signature was found.",
        meaning: "Android refuses to install unsigned packages; an unsigned file cannot be the release that users install.",
        action: "Sign the release with your upload key." });
    } else if (sig.v1 && !sig.v2 && !sig.v3) {
      findings.push({ id: "apk-v1-only", scanner: "apk", severity: "medium", category: "vulnerability", title: "Signed with the v1 scheme only",
        detail: "No v2/v3 APK Signature Scheme block; v1 does not protect every byte of the package.",
        meaning: "Android 7 and older accepted files that v1 signatures did not cover (Janus-style tampering).",
        action: "Enable v2 and v3 signing (apksigner)." });
    }
    if (sig.debugKey) {
      findings.push({ id: "apk-debug-key", scanner: "apk", severity: "high", category: "policy", title: "Signed with the Android debug key",
        detail: "The certificate's common name is \"Android Debug\".",
        meaning: "Debug-signed builds are not a release; anyone with the debug key can produce updates that replace the app.",
        action: "Sign with a dedicated release key that is kept private." });
    }
  }

  // DEX
  const dexEntries = z.entries.filter((e) => (isAab ? /^base\/dex\/classes\d*\.dex$/ : /^classes\d*\.dex$/).test(e.name));
  let dexTotal = 0;
  const dexFiles: Array<{ name: string; bytes: Buffer }> = [];
  for (const e of dexEntries) {
    if (dexTotal > MAX_DEX) break;
    const b = readZipEntry(buf, e, MAX_DEX - dexTotal);
    if (!b) continue;
    dexTotal += b.length;
    if (b.subarray(0, 4).toString("latin1") !== "dex\n") {
      findings.push({ id: `apk-bad-dex-${e.name}`, scanner: "apk", severity: "high", category: "vulnerability",
        title: `Invalid DEX file: ${e.name}`, detail: "The file does not start with the DEX magic.",
        meaning: "Invalid bytecode is either broken or hiding something from tools.", action: "Rebuild the package." });
      continue;
    }
    dexFiles.push({ name: e.name, bytes: b });
  }
  if (dexFiles.length) {
    const dex = scanDex(dexFiles, facts.permissions);
    findings.push(...dex.findings, ...hostFindings(dex.hosts));
    const secrets = await runSecretsAuditor(Buffer.from(dex.text, "latin1"), fileName);
    findings.push(...secrets.findings.map((f) => ({ ...f, id: `apk-${f.id}` })));
  }

  // Native libraries: must really be ELF, and packer shells are flagged.
  const libs = z.entries.filter((e) => (isAab ? /^base\/lib\/[^/]+\/[^/]+\.so$/ : /^lib\/[^/]+\/[^/]+\.so$/).test(e.name));
  const abis = [...new Set(libs.map((e) => e.name.split("/").slice(-2)[0]))];
  for (const e of libs) {
    const b = readZipEntry(buf, e, MAX_ASSET);
    if (b && sniffType(b) !== "elf") {
      findings.push({ id: `apk-fake-so-${e.name}`, scanner: "apk", severity: "critical", category: "trojan",
        title: `Fake native library: ${e.name}`, detail: `The file is ${sniffType(b).toUpperCase()}, not an ELF shared library.`,
        meaning: "Disguising other code as a native library hides it from review.", action: "Remove the file." });
    }
    if (PACKED_LIBS.test(e.name)) {
      findings.push({ id: `apk-packer-${e.name}`, scanner: "apk", severity: "medium", category: "packed",
        title: `Packer shell library: ${e.name}`, detail: "Known protection packers ship a library with this name.",
        meaning: "Packed code cannot be fully reviewed.", action: "Ship unprotected code for review." });
    }
  }

  // Payloads hidden in assets/res/raw
  const payloadEntries = z.entries.filter((e) => /(^|\/)(assets|res|raw)\//.test(e.name) && !e.encrypted && !e.symlink);
  let assetBytes = 0;
  for (const e of payloadEntries) {
    if (assetBytes > 64 * 1024 * 1024) break;
    const b = readZipEntry(buf, e, MAX_ASSET);
    if (!b) continue;
    assetBytes += b.length;
    const kind = sniffType(b);
    if (kind === "pe" || kind === "elf" || kind === "macho") {
      findings.push({ id: `apk-native-asset-${e.name}`, scanner: "apk", severity: "critical", category: "trojan",
        title: `Native executable hidden in ${e.name}`, detail: `Content is ${kind.toUpperCase()} despite its name.`,
        meaning: "Compiled code shipped as data is how droppers stage a second payload.", action: "Remove it from the package." });
    } else if (/\.(apk|dex|jar)$/i.test(e.name) || (kind === "zip" && /\.(apk|jar)$/i.test(e.name))) {
      findings.push({ id: `apk-embedded-${e.name}`, scanner: "apk", severity: "high", category: "trojan",
        title: `Package or bytecode embedded in assets: ${e.name}`, detail: "Installers and dynamic loaders ship a second package like this.",
        meaning: "A nested package can be installed or loaded after review.", action: "Remove it, or explain it and load only from the signed package." });
    }
  }

  const worst = findings.reduce((a, f) => Math.max(a, ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const)[f.severity]), 0);
  const penalty = findings.reduce((a, f) => a + ({ critical: 50, high: 22, medium: 9, low: 3, info: 0 } as const)[f.severity], 0);
  const sigText = sig ? [sig.v1 && "v1", sig.v2 && "v2", sig.v3 && "v3"].filter(Boolean).join("+") || "none" : "AAB (unsigned by design)";
  return {
    scanner: "apk",
    displayName: "Android package (APK/AAB)",
    verdict: worst >= 4 ? "malicious" : worst >= 2 ? "suspicious" : "clean",
    score: Math.max(0, 100 - penalty),
    durationMs: Date.now() - started,
    summary: `${isAab ? "AAB" : "APK"} ${facts.packageName ?? "(no package)"} ${facts.versionName ?? ""} · SDK ${facts.minSdk ?? "?"}–${facts.targetSdk ?? "?"} · ${facts.permissions.length} permissions · signing ${sigText} · ${dexFiles.length} dex · ${findings.length} finding(s).`,
    findings,
    meta: {
      packageName: facts.packageName ?? "",
      versionName: facts.versionName ?? "",
      versionCode: facts.versionCode ?? 0,
      minSdk: facts.minSdk ?? 0,
      targetSdk: facts.targetSdk ?? 0,
      targetSdkRequired: MIN_TARGET_SDK,
      permissions: facts.permissions.length,
      signing: sigText,
      signerDigest: sig?.signerDigest ?? "",
      dexFiles: dexFiles.length,
      abis: abis.join(", ") || "none",
      format: isAab ? "aab" : "apk",
    },
  };
}
