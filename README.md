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

- **VirusTotal Public API v3** — hash lookup, если файла нет — upload + poll analysis. Нужен `VIRUSTOTAL_API_KEY` (бесплатный community key: https://www.virustotal.com/gui/my-apikey). Без ключа движок возвращает `error`, эмуляция не подменяет результат.
- **ClamAV** — нативный `clamscan` + базы `/var/lib/clamav`.
- **ClamWin** — тот же ClamAV signature DB (продукт ClamWin на Windows); на сервере тоже native scan, не фейковый pass.

```bash
cp .env.example .env.local
# впишите VIRUSTOTAL_API_KEY=

# публичный туннель для теста
./scripts/start-public.sh
```

Данные: `data/store.json`, загрузки — `data/uploads/`.
