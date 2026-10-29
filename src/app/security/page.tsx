const engines = [
  {
    name: "VirusTotal",
    blurb:
      "Мультивендорный агрегат. При наличии VIRUSTOTAL_API_KEY — живой запрос по SHA256, иначе локальная эмуляция консенсуса.",
  },
  {
    name: "ClamAV",
    blurb:
      "Open-source антивирус. Если установлен clamscan/clamdscan — нативный скан файла, иначе слой эмуляции сигнатур.",
  },
  {
    name: "ClamWin",
    blurb:
      "Windows-ориентированный проход на сигнатурах ClamAV для .exe/.dll/.msi и типичных Windows-угроз.",
  },
  {
    name: "VibeGuard",
    blurb:
      "Собственные правила: Discord/Telegram эксфиль, пути браузерных cookie, крипто-кошельки, keylogger API, PowerShell cradle.",
  },
  {
    name: "Entropy Analyzer",
    blurb:
      "Shannon entropy пакует packed/encrypted payload — частый признак обфусцированных стиллеров.",
  },
  {
    name: "PE Inspector",
    blurb:
      "Проверка MZ/PE, числа секций, смеси network + credential импортов, фейковых «document.exe».",
  },
  {
    name: "Network Sink Scanner",
    blurb:
      "Достаёт URL из бинарника и помечает ngrok, pastebin, Discord webhooks, Telegram bot API, onion.",
  },
  {
    name: "Web Static Auditor",
    blurb:
      "Для HTML/JS: cookie exfil, eval, DOM XSS sinks, сторонние скрипты без SRI.",
  },
];

export default function SecurityPage() {
  return (
    <main className="mx-auto w-full max-w-6xl flex-1 px-5 pb-20 pt-6 md:px-8">
      <div className="anim-rise max-w-2xl">
        <p className="text-sm uppercase tracking-[0.16em] text-ink-soft">
          Безопасность
        </p>
        <h1 className="mt-2 font-display text-4xl font-extrabold tracking-tight md:text-5xl">
          Почему можно не бояться скачивать
        </h1>
        <p className="mt-4 text-ink-soft">
          Каждая сборка проходит конвейер из антивирусов и собственных
          эвристик. Пользователь видит score. Разработчик видит, можно ли
          выпускать продукт в массы — Ready / Needs fixes / Blocked.
        </p>
      </div>

      <ol className="anim-rise-delay-1 mt-12 space-y-0 border-t border-ink/10">
        {engines.map((e, i) => (
          <li
            key={e.name}
            className="grid gap-2 border-b border-ink/10 py-6 md:grid-cols-[140px_1fr] md:gap-8"
          >
            <div className="font-mono text-xs text-ink-soft">
              {String(i + 1).padStart(2, "0")}
            </div>
            <div>
              <h2 className="font-display text-xl font-semibold">{e.name}</h2>
              <p className="mt-1 max-w-2xl text-sm text-ink-soft">{e.blurb}</p>
            </div>
          </li>
        ))}
      </ol>

      <div className="anim-rise-delay-2 mt-12 rounded-[1.5rem] bg-ink px-6 py-8 text-[#cfe3db] md:px-10">
        <h2 className="font-display text-2xl font-bold text-white">
          Вердикт для релиза
        </h2>
        <ul className="mt-4 space-y-2 text-sm">
          <li>
            <strong className="text-teal-bright">Ready</strong> — score ≥ 75, нет
            critical/high → можно в массы.
          </li>
          <li>
            <strong className="text-amber">Needs fixes</strong> — есть
            подозрения → карантин, скачивание с предупреждением.
          </li>
          <li>
            <strong className="text-coral">Blocked</strong> — malware/stealer
            consensus → скачивание закрыто.
          </li>
        </ul>
      </div>
    </main>
  );
}
