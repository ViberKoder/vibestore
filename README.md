# Vibe Apps

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

## Вход через GitHub и импорт репозиториев

1. Создайте OAuth App: https://github.com/settings/developers → **New OAuth App**.
   - **Authorization callback URL:** `https://<ваш-домен>/api/auth/github/callback`
2. Задайте переменные окружения:
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` — из OAuth App (без них вход выключен);
   - `APP_URL=https://<ваш-домен>` — публичный адрес (для callback).
3. Вход запрашивает scope `read:user repo`: `repo` нужен, чтобы импортировать приватные репозитории.
   Токен хранится только в памяти сервера; после перезапуска нужно войти снова.

Импорт архива ограничен 200 МБ. Владелец импортированного приложения — ваш GitHub-аккаунт.

## Проверка сайтов

`/check` — проверка публичного адреса: TLS, заголовки безопасности, cookie, формы с паролем,
смешанный контент, эвристики по HTML и скриптам и VirusTotal по URL (нужен `VIRUSTOTAL_API_KEY`).
Адреса в приватных сетях, IP-литералы и порты кроме 80/443 отклоняются.

Дорожная карта и статус каждого этапа: `docs/ROADMAP.md`.

## Язык интерфейса

По умолчанию интерфейс на английском. Переключатель **EN / RU** в шапке сохраняет выбор в cookie `vibe_lang` (на год). Тексты пишутся в коде по-английски; русский перевод лежит в `src/lib/i18n/ru.ts` (генерируется из таблиц переводов), динамические фразы — в `RU_PATTERNS`. Отчёты сканирования хранятся на английском, поэтому переводятся при показе. Отчёты, созданные до этого изменения, содержат русский текст и обновятся после повторного скана.

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

## Деплой на Railway

В репозитории есть `Dockerfile` и `railway.json`: Railway соберёт образ сам (Nixpacks не подойдёт — нужен нативный ClamAV).

1. **New Project → Deploy from GitHub repo** и выберите этот репозиторий.
2. **Variables** сервиса:
   - `VIRUSTOTAL_API_KEY` — ключ из https://www.virustotal.com/gui/my-apikey (без него VirusTotal-движок вернёт ошибку и сборки не публикуются).
   - `VIBE_DATA_DIR=/data` — уже задан в образе, менять не нужно.
3. **Volume** (обязательно): Service → Settings → Volumes → добавьте том с mount path **`/data`**. Без него `store.json`, загрузки и иконки пропадут при каждом деплое.
4. **Replicas: 1.** Хранилище — JSON-файл на диске одного инстанса, несколько реплик не поддерживаются.
5. Память: берите не меньше 2 GB. `clamd` держит базу сигнатур в RAM (несколько сотен МБ), а крупные сборки (до 512 МБ) читаются при скане.

Что делает entrypoint (`scripts/railway-entrypoint.sh`): при старте подтягивает сигнатуры ClamAV (если их нет), запускает `clamd` и фоновый `freshclam -d` для обновлений, затем стартует Next.js на `$PORT`. Если `clamd` не поднялся, сканы идут через `clamscan` (медленнее, но корректно). `SKIP_CLAMAV=1` отключает ClamAV целиком — тогда ClamAV-движки будут сообщать об ошибке.

Health check: `GET /api/health`.

### Переменные окружения

| Переменная | Назначение | По умолчанию |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | ключ VirusTotal Public API | — |
| `VIBE_DATA_DIR` | каталог данных (store.json, uploads, media) | `./data` (в образе `/data`) |
| `PORT` | порт HTTP (Railway задаёт сам) | `3000` |
| `SKIP_CLAMAV` | `1` — не запускать ClamAV | `0` |

Локальный запуск Docker-образа: `docker build -t vibestore . && docker run -p 3000:3000 -v "$PWD/.vibe-data:/data" -e VIRUSTOTAL_API_KEY=... vibestore`.

