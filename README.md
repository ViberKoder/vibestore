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

Опционально:

```bash
export VIRUSTOTAL_API_KEY=...
# и/или установите clamav (clamscan)
```

Данные хранятся в `data/store.json`, загруженные файлы — в `data/uploads/`.
