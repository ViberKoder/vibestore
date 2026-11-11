# Vibe Store — security roadmap

The original plan (Stage A → B → C) was recovered from the project history and
brought up to date. Status is stated per item; nothing marked "done" is
hypothetical.

## Stage A — static auditor (done)

Runs without executing the build. Works on Electron `app.asar`, on ZIP packages
(including `.asar` nested inside them), and on raw uploads.

| Item | Status | Where |
| --- | --- | --- |
| Unpack `app.asar` (Electron) | done | `src/lib/security/asar.ts`, `src/lib/security/zip-read.ts` |
| Secrets in shipped code (AWS, Discord, tokens, …) | done, runs on unpacked source | `static-audit.ts` → `runSecretsAuditor` |
| Dangerous Electron flags (`nodeIntegration`, `contextIsolation`, `webSecurity`) | done, runs on unpacked source | `static-audit.ts` → `runElectronHardening` |
| Electron version / end-of-life check | done (heuristic: majors older than latest−2; `ELECTRON_LATEST_MAJOR` env) | `static-audit.ts` |
| External hosts by category (C2 / ads / analytics / CDN / code host) | done (curated host lists, heuristic) | `domains.ts` |
| Weight: native modules (`.node`), archive structure | done | `static-audit.ts`, `archive.ts` |
| Installer formats (NSIS `.exe`, MSI) | not unpacked — needs 7z/innoextract in the image | — |

Also part of Stage A's security layer: content sniffing (disguised executables),
ZIP structure checks (path traversal, symlinks, zip bombs, encrypted entries),
SHA-256 blocklist, rate limits, owner-only re-scans, security headers, and safe
download file names.

## Stage B — behavioural auditor (not implemented here)

Requires infrastructure this service does not have: a Windows VM or Firecracker
microVM, a network capture sandbox, and a 60-second idle measurement on real
hardware. Without that, any "behaviour" result would be invented.

Prepared hooks: the `EngineResult` contract accepts a `device-footprint`-style
result, so a sandbox runner can report keylogger/injection/persistence findings
and a Device Impact Score into the existing pillars without UI changes.

## Stage C — continuous audit (partly done)

| Item | Status |
| --- | --- |
| Developer reputation (apps, verified, blocked per account) | done — app page |
| Re-scan when VirusTotal/ClamAV signatures change | not done — needs a scheduled job and stored VT analysis IDs |
| Version diff ("what changed in the .exe") | not done — needs stored previous artifacts/hashes per app |

## Beyond the original plan (done)

- Website checker: public-only fetching (SSRF-safe connect-time DNS check, IP
  literals refused, port 80/443 only, redirects re-checked), TLS and security
  headers, cookies, password forms posting to other domains, mixed content,
  the content detectors on HTML and same-origin scripts, and VirusTotal URL lookup.
- GitHub sign-in (OAuth) and repository import: the source archive of a chosen
  branch/tag/commit goes through the same scanners. Ownership is tied to the
  GitHub account. Tokens stay on the server, in memory, and are never sent to
  the archive host after the first request.
