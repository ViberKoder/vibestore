# Vibe Store

Безопасный App Store для вайбкодерских приложений: сайты, утилиты, `.exe` и другие сборки проходят мультидвижковый скан до публикации.

## Возможности

- Каталог с фильтром «только проверенные»
- Публикация сборок (до 64 МБ): exe, zip, html, dmg, apk…
- Пайплайн сканирования:
  - **VirusTotal** (live при `VIRUSTOTAL_API_KEY`, иначе эмуляция)
  - **ClamAV** (native `clamscan` / эмуляция)
  - **ClamWin** (Windows-сигнатуры ClamAV)
  - **VibeGuard**, Entropy, PE Inspector, Network Sink, Web Static
- Security score + readiness: Ready / Needs fixes / Blocked
- Кабинет разработчика

## Запуск

```bash
npm install
npm run dev
```

Откройте [http://localhost:3000](http://localhost:3000).

## Антивирусы (без обходов)

- **VirusTotal Public API v3** — hash lookup; если файла нет — upload (≤32 МБ) или `upload_url` (крупные .exe до сотен МБ). Ключ только в env.
- **ClamAV / ClamWin** — нативный `clamscan`, без эмуляции-обхода.
- Живой прогресс скана по каждому движку на странице приложения.
- Лимит загрузки: **512 МБ** (удобно для ~200 МБ installers).

```bash
cp .env.example .env.local
# VIRUSTOTAL_API_KEY=...

npm run dev
# или публичный туннель:
./scripts/start-public.sh
```

Данные: `data/store.json`, загрузки — `data/uploads/`. Фейковых seed-приложений нет.
