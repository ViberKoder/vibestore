import type { AppKind, ThreatFinding } from "../types";

type AppCtx = {
  name: string;
  kind: AppKind | string;
  fileName: string;
  version: string;
  tagline: string;
};

/**
 * Builds a ready-to-paste prompt for Cursor / Claude / Codex so the developer
 * can hand the finding to an agent and get a concrete fix.
 */
export function buildAgentPrompt(
  finding: ThreatFinding,
  app: AppCtx,
): string {
  const action = finding.action?.trim();
  const meaning = finding.meaning?.trim();

  return [
    `# Vibe Audit fix task`,
    ``,
    `You are fixing a security / quality finding from Vibe Store audit for the app **${app.name}** (${app.kind}, file \`${app.fileName}\`, v${app.version}).`,
    app.tagline ? `Product: ${app.tagline}` : null,
    ``,
    `## Finding`,
    `- ID: \`${finding.id}\``,
    `- Scanner: ${finding.scanner}`,
    `- Severity: ${finding.severity}`,
    `- Category: ${finding.category}`,
    `- Title: ${finding.title}`,
    ``,
    `### Detail`,
    finding.detail,
    meaning ? `\n### Why it matters\n${meaning}` : null,
    action ? `\n### Suggested fix direction\n${action}` : null,
    ``,
    `## Your job`,
    `1. Locate the code / config / build flags that cause this finding.`,
    `2. Apply the minimal safe fix (do not invent unrelated refactors).`,
    `3. Explain what you changed and how to verify (rebuild, re-scan, or unit check).`,
    `4. If the finding is a false positive for this product type, say so and propose how to document / suppress it safely — do not silently ignore real risk.`,
    `5. Do not weaken security to "make the score green". Prefer secure defaults.`,
    ``,
    `Start by searching the repo for related strings, flags, and dependencies, then patch.`,
  ]
    .filter((line) => line !== null)
    .join("\n");
}

export function enrichFindingsWithPrompts<T extends ThreatFinding>(
  findings: T[],
  app: AppCtx,
): T[] {
  return findings.map((f) =>
    f.agentPrompt
      ? f
      : { ...f, agentPrompt: buildAgentPrompt(f, app) },
  );
}
