import Link from "next/link";
import { getT } from "@/lib/i18n/server";

const engines = [
  {
    name: "VirusTotal",
    blurb:
      "Multi-vendor aggregate. With VIRUSTOTAL_API_KEY — a live lookup by SHA256, otherwise a local consensus emulation.",
  },
  {
    name: "ClamAV",
    blurb:
      "Open-source antivirus. Native clamscan when available, otherwise a signature emulation layer.",
  },
  {
    name: "ClamWin",
    blurb:
      "Windows-oriented pass with ClamAV signatures for .exe/.dll/.msi.",
  },
  {
    name: "VibeGuard",
    blurb:
      "Our own rules: Discord/Telegram exfiltration, cookie paths, crypto wallets, keylogger APIs.",
  },
  {
    name: "Entropy Analyzer",
    blurb: "Shannon entropy — packed/encrypted payloads and obfuscation.",
  },
  {
    name: "PE Inspector",
    blurb:
      "MZ/PE, sections, a mix of network and credential imports, fake document.exe files.",
  },
  {
    name: "Network Sink Scanner",
    blurb: "URLs in the binary: ngrok, pastebin, Discord webhooks, Telegram bot API.",
  },
  {
    name: "Web Static Auditor",
    blurb: "HTML/JS: cookie exfiltration, eval, DOM XSS, third-party scripts without SRI.",
  },
];

export default async function SecurityPage() {
  const t = await getT();
  return (
    <main className="flex-1 pb-20 pt-8 md:pt-12">
      <div className="container-store">
        <div className="fade-up max-w-2xl">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            {t("Security")}
          </p>
          <h1 className="mt-2 text-[36px] font-extrabold tracking-[-0.045em] md:text-[48px]">
            {t("Why downloading here is safer")}
          </h1>
          <p className="mt-4 text-[17px] leading-relaxed text-ink-2">
            {t(
              "Every build goes through a pipeline of antivirus engines and our own heuristics. Users see a score. Developers see whether the build can go out to everyone.",
            )}
          </p>
          <Link href="/publish" className="btn-primary mt-7 inline-flex">
            {t("Check your build")}
          </Link>
        </div>

        <ol className="fade-up-d1 mt-14 divide-y divide-black/[0.06] border-y border-black/[0.06]">
          {engines.map((e, i) => (
            <li
              key={e.name}
              className="grid gap-2 py-6 md:grid-cols-[100px_1fr] md:gap-10"
            >
              <div className="text-[13px] font-semibold tabular-nums text-ink-3">
                {String(i + 1).padStart(2, "0")}
              </div>
              <div>
                <h2 className="text-[18px] font-bold tracking-[-0.02em]">
                  {t(e.name)}
                </h2>
                <p className="mt-1 max-w-2xl text-[14px] leading-relaxed text-ink-2">
                  {t(e.blurb)}
                </p>
              </div>
            </li>
          ))}
        </ol>

        <div className="fade-up-d2 mt-12 grid gap-4 md:grid-cols-3">
          <Verdict
            title={t("Ready")}
            tone="ready"
            text={t("Score ≥ 75, no critical/high findings — can go out to everyone.")}
          />
          <Verdict
            title={t("Needs fixes")}
            tone="warn"
            text={t("Something is suspicious — quarantined, downloads come with a warning.")}
          />
          <Verdict
            title={t("Blocked")}
            tone="danger"
            text={t("Malware or stealer consensus — downloads are closed.")}
          />
        </div>
      </div>
    </main>
  );
}

function Verdict({
  title,
  text,
  tone,
}: {
  title: string;
  text: string;
  tone: "ready" | "warn" | "danger";
}) {
  const color =
    tone === "ready"
      ? "text-green-ink bg-green-soft"
      : tone === "warn"
        ? "text-amber-ink bg-amber-soft"
        : "text-red-ink bg-red-soft";
  return (
    <div className="surface-card p-6">
      <span
        className={`inline-flex rounded-full px-2.5 py-1 text-[12px] font-semibold ${color}`}
      >
        {title}
      </span>
      <p className="mt-3 text-[14px] leading-relaxed text-ink-2">{text}</p>
    </div>
  );
}
