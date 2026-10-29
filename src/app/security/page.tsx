import Link from "next/link";

const engines = [
  {
    name: "VirusTotal",
    blurb:
      "Мультивендорный агрегат. При VIRUSTOTAL_API_KEY — живой запрос по SHA256, иначе локальная эмуляция консенсуса.",
  },
  {
    name: "ClamAV",
    blurb:
      "Open-source антивирус. Native clamscan при наличии, иначе слой эмуляции сигнатур.",
  },
  {
    name: "ClamWin",
    blurb:
      "Windows-ориентированный проход на сигнатурах ClamAV для .exe/.dll/.msi.",
  },
  {
    name: "VibeGuard",
    blurb:
      "Собственные правила: Discord/Telegram эксфиль, cookie-пути, крипто-кошельки, keylogger API.",
  },
  {
    name: "Entropy Analyzer",
    blurb: "Shannon entropy — packed/encrypted payload и обфускация.",
  },
  {
    name: "PE Inspector",
    blurb:
      "MZ/PE, секции, смесь network + credential импортов, фейковые document.exe.",
  },
  {
    name: "Network Sink Scanner",
    blurb: "URL из бинарника: ngrok, pastebin, Discord webhooks, Telegram bot API.",
  },
  {
    name: "Web Static Auditor",
    blurb: "HTML/JS: cookie exfil, eval, DOM XSS, сторонние скрипты без SRI.",
  },
];

export default function SecurityPage() {
  return (
    <main className="flex-1 pb-20 pt-8 md:pt-12">
      <div className="container-store">
        <div className="fade-up max-w-2xl">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            Безопасность
          </p>
          <h1 className="mt-2 text-[36px] font-extrabold tracking-[-0.045em] md:text-[48px]">
            Почему скачивать здесь спокойнее
          </h1>
          <p className="mt-4 text-[17px] leading-relaxed text-ink-2">
            Каждая сборка проходит конвейер антивирусов и собственных эвристик.
            Пользователь видит score. Разработчик — можно ли выпускать в массы.
          </p>
          <Link href="/publish" className="btn-primary mt-7 inline-flex">
            Проверить свою сборку
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
                  {e.name}
                </h2>
                <p className="mt-1 max-w-2xl text-[14px] leading-relaxed text-ink-2">
                  {e.blurb}
                </p>
              </div>
            </li>
          ))}
        </ol>

        <div className="fade-up-d2 mt-12 grid gap-4 md:grid-cols-3">
          <Verdict
            title="Ready"
            tone="ready"
            text="Score ≥ 75, нет critical/high — можно в массы."
          />
          <Verdict
            title="Needs fixes"
            tone="warn"
            text="Есть подозрения — карантин, скачивание с предупреждением."
          />
          <Verdict
            title="Blocked"
            tone="danger"
            text="Malware/stealer consensus — скачивание закрыто."
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
