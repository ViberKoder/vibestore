import type { EngineResult, ThreatFinding } from "../types";
import { inspectZip, isUnsafeEntryName } from "../security/archive";
import { judgeType } from "../security/filetype";
import { blocklistSize, isBlocked } from "../security/blocklist";

const GB = 1024 ** 3;
const MB = 1024 ** 2;

function verdictOf(findings: ThreatFinding[]): EngineResult["verdict"] {
  if (findings.some((f) => f.severity === "critical")) return "malicious";
  if (findings.some((f) => f.severity === "high" || f.severity === "medium")) return "suspicious";
  return "clean";
}

function scoreOf(findings: ThreatFinding[]): number {
  const penalty = findings.reduce(
    (a, f) => a + ({ critical: 60, high: 30, medium: 12, low: 4, info: 0 } as const)[f.severity],
    0,
  );
  return Math.max(0, 100 - penalty);
}

function finding(
  scanner: ThreatFinding["scanner"],
  id: string,
  severity: ThreatFinding["severity"],
  category: ThreatFinding["category"],
  title: string,
  detail: string,
  meaning: string,
  action: string,
): ThreatFinding {
  return { id, scanner, severity, category, title, detail, meaning, action };
}

/**
 * Content sniffing + archive structure. Catches what extension-based checks
 * miss: executables renamed to documents/images, zip-slip paths, symlinks that
 * escape the folder, zip bombs, password-protected archives (hidden payloads).
 */
export async function runArchiveEngine(buf: Buffer, fileName: string): Promise<EngineResult> {
  const started = Date.now();
  const findings: ThreatFinding[] = [];
  const types = judgeType(fileName, buf);

  if (types.disguisedExecutable) {
    findings.push(
      finding(
        "archive",
        "arc-disguised-exe",
        "critical",
        "trojan",
        "Executable disguised as a non-executable file",
        `«${fileName}» is a ${types.sniffed.toUpperCase()} binary but its extension says otherwise.`,
        "Renaming an executable to look like a document or image is the classic way to get users to run malware.",
        "Ship the real file with its real extension. If this is a script, use .sh/.ps1/.js.",
      ),
    );
  } else if (types.mismatch) {
    findings.push(
      finding(
        "archive",
        "arc-type-mismatch",
        "high",
        "policy",
        "File content does not match its extension",
        `«${fileName}» is detected as ${types.sniffed.toUpperCase()}.`,
        "A mismatched extension confuses scanners and users and is a common evasion trick.",
        "Re-export or rebuild the package so the extension matches its content.",
      ),
    );
  }

  let archiveNote: string | undefined;
  if (types.sniffed === "zip") {
    const z = inspectZip(buf);
    if (z.format !== "zip") {
      findings.push(
        finding("archive", "arc-unreadable", "medium", "policy", "Archive could not be read",
          `Central directory check failed: ${z.reason ?? "unknown"}.`,
          "An archive the scanner cannot read cannot be verified.",
          "Rebuild the archive with a standard tool (zip/7z/tar) and upload again."),
      );
    } else {
      archiveNote = `${z.entries.length} entries`;
      const unsafe = z.entries.filter((e) => isUnsafeEntryName(e.name));
      if (unsafe.length) {
        findings.push(
          finding("archive", "arc-zip-slip", "critical", "trojan", "Path traversal inside archive",
            `${unsafe.length} entr${unsafe.length === 1 ? "y" : "ies"} use absolute paths or "..", e.g. «${unsafe[0].name}».`,
            "Extractors that trust these paths can overwrite files outside the install folder (zip-slip).",
            "Build the archive from relative paths only."),
        );
      }
      const links = z.entries.filter((e) => e.symlink);
      if (links.length) {
        findings.push(
          finding("archive", "arc-symlink", "high", "trojan", "Symbolic links inside archive",
            `${links.length} symlink${links.length === 1 ? "" : "s"}, e.g. «${links[0].name}».`,
            "A symlink can point outside the folder and redirect later writes to system files.",
            "Replace symlinks with real files or remove them from the package."),
        );
      }
      const encrypted = z.entries.filter((e) => e.encrypted);
      if (encrypted.length) {
        findings.push(
          finding("archive", "arc-encrypted", "high", "policy", "Password-protected entries",
            `${encrypted.length} encrypted entr${encrypted.length === 1 ? "y" : "ies"} cannot be inspected.`,
            "Encrypted payloads hide content from every scanner, including ours.",
            "Publish the package unencrypted; the store does not accept password-protected builds."),
        );
      }
      if (z.totalUncompressed > 1 * GB && z.totalCompressed > 0 && z.totalUncompressed / z.totalCompressed > 100) {
        findings.push(
          finding("archive", "arc-bomb", "high", "policy", "Possible zip bomb",
            `Declared size ${(z.totalUncompressed / GB).toFixed(1)} GB from ${(z.totalCompressed / MB).toFixed(1)} MB.`,
            "Such archives exhaust memory and disk when extracted, which can crash or freeze the user's machine.",
            "Remove generated or duplicated data from the package."),
        );
      }
      const bigEntry = z.entries.find((e) => e.uncompressedSize > 100 * MB && e.compressedSize > 0 && e.uncompressedSize / e.compressedSize > 1000);
      if (bigEntry) {
        findings.push(
          finding("archive", "arc-bomb-entry", "high", "policy", "Extreme compression ratio on one entry",
            `«${bigEntry.name}» expands to ${(bigEntry.uncompressedSize / MB).toFixed(0)} MB.`,
            "Extreme ratios are typical for bombs and for hiding data.",
            "Check the file; ship the real asset instead of a padded one."),
        );
      }
      if (z.truncated) {
        findings.push(
          finding("archive", "arc-too-many", "medium", "policy", "Very large number of entries",
            "The archive has more entries than the inspector reads (50 000+).",
            "Huge entry counts slow down extraction and can hide a few malicious files among thousands.",
            "Ship only the files the product needs."),
        );
      }
      const executables = z.entries.filter((e) => e.executable);
      if (executables.length) {
        findings.push(
          finding("archive", "arc-executables", "medium", "policy",
            `${executables.length} executable or script file${executables.length === 1 ? "" : "s"} inside the package`,
            executables.slice(0, 5).map((e) => e.name).join(", "),
            "Each executable inside the package runs with the user's permissions after installation.",
            "Confirm every bundled executable is part of the product and documented."),
        );
      }
      const nested = z.entries.filter((e) => e.nested);
      if (nested.length) {
        findings.push(
          finding("archive", "arc-nested", "medium", "policy", "Nested archives inside the package",
            `${nested.length} nested archive${nested.length === 1 ? "" : "s"}, e.g. «${nested[0].name}». Their contents are not inspected.`,
            "Nested archives are a way to hide payloads from shallow scanners.",
            "Unpack nested archives into the package."),
        );
      }
      if (z.zip64) {
        findings.push(
          finding("archive", "arc-zip64", "low", "other", "ZIP64 archive",
            "Large ZIP64 archives are read structurally only.",
            "Structural checks ran, but file contents were not expanded.",
            "Prefer packages under 4 GB for full inspection."),
        );
      }
    }
  } else if (types.sniffed === "rar" || types.sniffed === "7z") {
    findings.push(
      finding("archive", "arc-opaque", "medium", "policy", `${types.sniffed.toUpperCase()} archive hides its contents`,
        "The package format cannot be inspected structurally here.",
        "Opaque containers are the most common way to smuggle payloads past review.",
        "Repackage as ZIP so the store can inspect every entry."),
    );
  }

  const verdict = verdictOf(findings);
  return {
    scanner: "archive",
    displayName: "Archive & type inspector",
    verdict,
    score: scoreOf(findings),
    durationMs: Date.now() - started,
    summary: findings.length
      ? `Archive/type: ${findings.length} finding(s)${archiveNote ? ` · ${archiveNote}` : ""}.`
      : `Archive/type: content matches the extension${archiveNote ? ` · ${archiveNote}` : ""}.`,
    findings,
    meta: { sniffed: types.sniffed, ...(archiveNote ? { archive: archiveNote } : {}) },
  };
}

/** Known-bad hash lookup (operator-maintained blocklist). */
export async function runBlocklistEngine(sha256: string): Promise<EngineResult> {
  const started = Date.now();
  const hit = await isBlocked(sha256);
  const findings: ThreatFinding[] = hit
    ? [
        finding("blocklist", "bl-hit", "critical", "virus", "Known-bad build (blocklist)",
          `SHA-256 ${sha256.slice(0, 16)}… is on the store blocklist.`,
          "This exact file was reported as malicious before.",
          "Build a new artifact from clean sources. The store will not publish this file."),
      ]
    : [];
  return {
    scanner: "blocklist",
    displayName: "Blocklist",
    verdict: hit ? "malicious" : "clean",
    score: hit ? 0 : 100,
    durationMs: Date.now() - started,
    summary: hit
      ? "Blocklist: this build hash is on the list."
      : `Blocklist: not listed (${blocklistSize()} entries loaded).`,
    findings,
    meta: { sha256 },
  };
}
