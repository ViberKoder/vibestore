# Vibe Apps — security roadmap

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

## Product direction: an independent auditor (Vibe Apps)

The goal: an independent auditor that answers four questions about a build:

1. Is the code free of known-malicious and dangerous behaviour?
2. Can it harm users (stealing data, tracking, scams)?
3. Can the app be broken into (insecure runtime, outdated components, known CVEs)?
4. Does it slow the device down (CPU, RAM, disk, autostart)?

**What "100% safe" can and cannot mean.** No static or dynamic analysis proves
that software is free of all bugs or backdoors. Vibe Apps therefore does not
publish a "100% safe" verdict. Every report states its coverage: how many
checks ran, which passed, which were not applicable or unavailable, and what is
never verified (see the "Not verified by this report" block). The verdict
means "no blocking findings in the checks listed", and the report says so.

### What each question depends on today

| Question | Covered now | Missing (and what it needs) |
| --- | --- | --- |
| 1. Malicious code | signatures (ClamAV, VirusTotal, VibeGuard), blocklist, Stage A unpacking | runtime behaviour → sandbox (Stage B) |
| 2. Harm to users | trackers, ad networks, C2-style endpoints, password forms, mixed content | consent/UX review stays manual |
| 3. Breakable | Electron flags, end-of-life runtime, secrets, HTTP/TLS/headers | dependency CVEs → OSV lookup (next step) |
| 4. Device slowdown | size, native modules, miner/autostart heuristics | measured CPU/RAM → sandbox (Stage B) |

### Next steps, in order

1. **Dependency CVEs (OSV).** Parse `package-lock.json` / `package.json` found
   inside the package and ZIP sources, query the OSV API (`api.osv.dev`), and
   report advisories with severity. Needs outbound access from the server.
2. **Source pinning for imports.** Record the Git commit SHA of every imported
   repository in the report, so a verdict refers to exact source.
3. **Stage B sandbox.** A Windows VM or microVM runner that executes the build
   for 60 seconds and reports file writes, network destinations, processes,
   keyboard hooks and idle CPU/RAM. Needs a host with virtualisation; the report
   model already accepts such results as engines.
4. **Public verification log.** Keep scan history per build hash, so a later
   change in verdict is visible instead of silent.
