import path from "path";
import type { EngineResult, ThreatFinding } from "../types";
import {
  collectAsciiStrings,
  extractSearchText,
  looksLikeElectron,
} from "./extract";
import { inspectPe } from "./pe";
import { sampleEntropy } from "./entropy";

const SECRET_PATTERNS: Array<{
  id: string;
  title: string;
  pattern: RegExp;
  severity: ThreatFinding["severity"];
}> = [
  {
    id: "aws-key",
    title: "Возможный AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
  },
  {
    id: "github-pat",
    title: "Возможный GitHub token",
    pattern: /gh[pousr]_[A-Za-z0-9_]{20,}/g,
    severity: "critical",
  },
  {
    id: "slack-token",
    title: "Возможный Slack token",
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    severity: "high",
  },
  {
    id: "generic-api-key",
    title: "Жёстко прошитый API key / secret",
    pattern:
      /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"']{12,}["']/gi,
    severity: "high",
  },
  {
    id: "private-key",
    title: "Приватный ключ в бинарнике",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
  },
  {
    id: "jwt-secret",
    title: "Похоже на JWT / bearer secret",
    pattern: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: "medium",
  },
];

const TRACKER_DOMAINS: Array<{ host: string; label: string; severity: ThreatFinding["severity"] }> =
  [
    { host: "google-analytics.com", label: "Google Analytics", severity: "low" },
    { host: "googletagmanager.com", label: "Google Tag Manager", severity: "low" },
    { host: "facebook.com/tr", label: "Facebook Pixel", severity: "medium" },
    { host: "amplitude.com", label: "Amplitude", severity: "low" },
    { host: "mixpanel.com", label: "Mixpanel", severity: "low" },
    { host: "sentry.io", label: "Sentry", severity: "low" },
    { host: "hotjar.com", label: "Hotjar", severity: "medium" },
    { host: "fullstory.com", label: "FullStory", severity: "medium" },
    { host: "segment.io", label: "Segment", severity: "low" },
    { host: "segment.com", label: "Segment", severity: "low" },
    { host: "appsflyer.com", label: "AppsFlyer", severity: "medium" },
    { host: "adjust.com", label: "Adjust", severity: "medium" },
    { host: "clarity.ms", label: "Microsoft Clarity", severity: "medium" },
    { host: "doubleclick.net", label: "DoubleClick ads", severity: "medium" },
  ];

function scoreFromFindings(findings: ThreatFinding[]): number {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  return Math.max(0, 100 - critical * 35 - high * 18 - medium * 8 - low * 3);
}

function verdictFromFindings(findings: ThreatFinding[]): EngineResult["verdict"] {
  if (findings.some((f) => f.severity === "critical")) return "malicious";
  if (findings.some((f) => f.severity === "high")) return "suspicious";
  if (findings.length) return "suspicious";
  return "clean";
}

/** Hardcoded secrets / credentials auditor */
export async function runSecretsAuditor(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const text = extractSearchText(buf);
  const findings: ThreatFinding[] = [];

  for (const sig of SECRET_PATTERNS) {
    const matches = text.match(sig.pattern);
    if (!matches?.length) continue;
    const sample = matches[0].slice(0, 24);
    findings.push({
      id: `sec-${sig.id}`,
      scanner: "secrets",
      severity: sig.severity,
      title: sig.title,
      detail: `Найдено совпадений: ${matches.length}. Пример (обрезано): ${sample}…`,
      category: "vulnerability",
      meaning:
        "Секреты в клиентской сборке может вытащить любой пользователь — это прямой риск взлома бэкенда/аккаунтов.",
      action:
        "Уберите ключи из бинарника. Используйте серверную выдачу токенов и ротацию уже утекших секретов.",
    });
  }

  if (/password\s*[:=]\s*["'][^"']{4,}["']/i.test(text)) {
    findings.push({
      id: "sec-password-literal",
      scanner: "secrets",
      severity: "high",
      title: "Литерал password в сборке",
      detail: "Обнаружена строка вида password=… внутри файла.",
      category: "vulnerability",
      meaning: "Пароли в клиенте почти всегда компрометируются.",
      action: "Удалите захардкоженные пароли; храните только на сервере.",
    });
  }

  return {
    scanner: "secrets",
    displayName: "Secrets Auditor",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? `Секретов в строках ${fileName} не найдено.`
        : `Найдено потенциальных секретов: ${findings.length}.`,
    findings,
    meta: { pillar: "hardening" },
  };
}

/** Electron / Chromium hardening checks (static string heuristics). */
export async function runElectronHardening(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const text = extractSearchText(buf, 4_000_000);
  const findings: ThreatFinding[] = [];
  const electron = looksLikeElectron(text);
  const looksJsBundle =
    /\.(js|html|asar)$/i.test(fileName) || /nodeIntegration|BrowserWindow/i.test(text);

  if (!electron && !looksJsBundle && !/\.(exe|dmg|appimage|zip)$/i.test(fileName)) {
    return {
      scanner: "electron-hardening",
      displayName: "Electron Hardening",
      verdict: "skipped",
      score: 100,
      durationMs: Date.now() - started,
      summary: "Не похоже на Electron/Chromium-цель — пропуск.",
      findings: [],
      meta: { skipped: true, pillar: "hardening" },
    };
  }

  if (!electron && /\.(exe|dmg)$/i.test(fileName)) {
    // Still run light checks; mark as limited
  }

  if (/nodeIntegration["']?\s*:\s*true/i.test(text) || /nodeIntegration:\s*!0/i.test(text)) {
    findings.push({
      id: "el-node-integration",
      scanner: "electron-hardening",
      severity: "critical",
      title: "nodeIntegration: true",
      detail: "Renderer может получать Node API — XSS становится RCE.",
      category: "vulnerability",
      meaning:
        "Любая XSS в интерфейсе может выполнить произвольный код на машине пользователя.",
      action: "Выключите nodeIntegration и используйте contextBridge + preload.",
    });
  }

  if (/contextIsolation["']?\s*:\s*false/i.test(text) || /contextIsolation:\s*!1/i.test(text)) {
    findings.push({
      id: "el-no-isolation",
      scanner: "electron-hardening",
      severity: "high",
      title: "contextIsolation: false",
      detail: "Изоляция контекста отключена — опасный Electron-default прошлых лет.",
      category: "vulnerability",
      meaning: "Страница может лезть в privileged preload/API.",
      action: "Включите contextIsolation: true во всех BrowserWindow.",
    });
  }

  if (/webSecurity["']?\s*:\s*false/i.test(text)) {
    findings.push({
      id: "el-websecurity-off",
      scanner: "electron-hardening",
      severity: "high",
      title: "webSecurity: false",
      detail: "Отключена web security Chromium (CORS/SOP ослаблены).",
      category: "vulnerability",
      meaning: "Упрощает XSS и подгрузку чужого контента.",
      action: "Держите webSecurity: true; не отключайте без крайней нужды.",
    });
  }

  if (/allowRunningInsecureContent["']?\s*:\s*true/i.test(text)) {
    findings.push({
      id: "el-insecure-content",
      scanner: "electron-hardening",
      severity: "medium",
      title: "allowRunningInsecureContent",
      detail: "Разрешён mixed content (HTTP внутри HTTPS/приложения).",
      category: "vulnerability",
      meaning: "Трафик можно подменить в локальной сети.",
      action: "Отключите insecure content; используйте только HTTPS.",
    });
  }

  const electronVer = text.match(/Electron\/(\d+\.\d+\.\d+)/i)?.[1];
  if (electronVer) {
    const major = Number(electronVer.split(".")[0]);
    if (major > 0 && major < 22) {
      findings.push({
        id: "el-old-runtime",
        scanner: "electron-hardening",
        severity: "high",
        title: `Устаревший Electron ${electronVer}`,
        detail: "Старые Chromium/Electron часто содержат публичные CVE.",
        category: "vulnerability",
        meaning: "Известные дыры в runtime = готовый вектор взлома приложения.",
        action: "Обновите Electron до поддерживаемой LTS и пересоберите.",
      });
    }
  }

  if (/openDevTools\(|devTools:\s*true/i.test(text) && /production|app\.isPackaged/i.test(text)) {
    findings.push({
      id: "el-devtools-prod",
      scanner: "electron-hardening",
      severity: "low",
      title: "DevTools могут быть доступны в релизе",
      detail: "Признаки openDevTools/devTools:true рядом с production-кодом.",
      category: "policy",
      meaning: "Упрощает реверс и кражу токенов из renderer.",
      action: "Отключайте DevTools в production-сборках.",
    });
  }

  const score = scoreFromFindings(findings);
  return {
    scanner: "electron-hardening",
    displayName: "Electron Hardening",
    verdict: electron || findings.length ? verdictFromFindings(findings) : "skipped",
    score: electron || findings.length ? score : 100,
    durationMs: Date.now() - started,
    summary: electron
      ? findings.length
        ? `Electron-сборка: ${findings.length} проблем hardening.`
        : `Electron detected${electronVer ? ` (${electronVer})` : ""} — опасных флагов не видно.`
      : findings.length
        ? `Найдены Electron-подобные флаги: ${findings.length}.`
        : "Явных Electron-маркеров нет — ограниченная проверка.",
    findings,
    meta: {
      pillar: "hardening",
      electronDetected: electron,
      electronVersion: electronVer ?? "unknown",
    },
  };
}

/** Privacy / trackers / analytics domain auditor */
export async function runPrivacyAuditor(buf: Buffer): Promise<EngineResult> {
  const started = Date.now();
  const text = extractSearchText(buf);
  const findings: ThreatFinding[] = [];
  const hits: string[] = [];

  for (const t of TRACKER_DOMAINS) {
    if (text.toLowerCase().includes(t.host.toLowerCase())) {
      hits.push(t.label);
      findings.push({
        id: `priv-${t.host.replace(/\W+/g, "-")}`,
        scanner: "privacy",
        severity: t.severity,
        title: `Трекер / аналитика: ${t.label}`,
        detail: `В сборке встречается хост ${t.host}`,
        category: "policy",
        meaning:
          "Аналитика и пиксели собирают поведение пользователей. Для вайб-продукта это вопрос доверия и иногда GDPR.",
        action:
          "Задокументируйте трекеры в карточке приложения, дайте opt-out или уберите лишнее.",
      });
    }
  }

  if (/navigator\.geolocation|getCurrentPosition/i.test(text)) {
    findings.push({
      id: "priv-geo",
      scanner: "privacy",
      severity: "medium",
      title: "Запрос геолокации",
      detail: "В коде есть navigator.geolocation / getCurrentPosition.",
      category: "policy",
      meaning: "Геолокация — чувствительные данные; без явной пользы это лишний риск.",
      action: "Запрашивайте гео только по действию пользователя и объясните зачем.",
    });
  }

  if (/mediaDevices\.getUserMedia|getUserMedia\s*\(/i.test(text)) {
    findings.push({
      id: "priv-media",
      scanner: "privacy",
      severity: "medium",
      title: "Доступ к камере / микрофону",
      detail: "Обнаружен getUserMedia.",
      category: "policy",
      meaning: "Камера/микрофон — высокий уровень приватности.",
      action: "Просите разрешение явно и только когда функция реально нужна.",
    });
  }

  // clipboard / screenshot-ish
  if (/clipboard\.read|readText\(|desktopCapturer/i.test(text)) {
    findings.push({
      id: "priv-clipboard",
      scanner: "privacy",
      severity: "high",
      title: "Чтение буфера обмена / захват экрана",
      detail: "API clipboard/desktopCapturer в сборке.",
      category: "stealer",
      meaning: "Так часто выглядят стиллеры и «тихое» слежение.",
      action: "Убедитесь, что это заявленная функция; иначе удалите.",
    });
  }

  return {
    scanner: "privacy",
    displayName: "Privacy Auditor",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? "Явных трекеров и чувствительных privacy-API не видно."
        : `Privacy: ${findings.length} сигнал(ов)${hits.length ? ` · ${[...new Set(hits)].slice(0, 4).join(", ")}` : ""}.`,
    findings,
    meta: { pillar: "privacy", trackers: hits.join(",") || "none" },
  };
}

/** Device footprint / performance risk heuristics */
export async function runDeviceFootprint(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const findings: ThreatFinding[] = [];
  const sizeMb = buf.length / (1024 * 1024);
  const text = extractSearchText(buf, 2_000_000);
  const entropy = sampleEntropy(buf);

  if (sizeMb >= 250) {
    findings.push({
      id: "fp-huge",
      scanner: "device-footprint",
      severity: "medium",
      title: `Очень большой дистрибутив (${sizeMb.toFixed(0)} МБ)`,
      detail: "Тяжёлые установщики дольше качаются и занимают диск.",
      category: "performance",
      meaning: "Плохой UX на слабых ПК и мобильном интернете; чаще «вечный» апдейт.",
      action: "Сжмите ассеты, уберите лишние runtime, разбейте на optional components.",
    });
  } else if (sizeMb >= 120) {
    findings.push({
      id: "fp-large",
      scanner: "device-footprint",
      severity: "low",
      title: `Крупный дистрибутив (${sizeMb.toFixed(0)} МБ)`,
      detail: "Размер заметный для десктоп-утилиты.",
      category: "performance",
      meaning: "Не баг, но пользователи на HDD/слабом Wi‑Fi почувствуют.",
      action: "Проверьте, нужен ли полный Chromium/Electron стек.",
    });
  }

  if (/stratum\+|xmrig|coinhive|cryptonight|ethash|NiceHash/i.test(text)) {
    findings.push({
      id: "fp-miner",
      scanner: "device-footprint",
      severity: "critical",
      title: "Признаки криптомайнера",
      detail: "В строках есть mining/pool индикаторы.",
      category: "virus",
      meaning: "Майнинг жрёт CPU/GPU и батарею — прямой вред устройству.",
      action: "Удалите майнер. Такие сборки блокируются стором.",
    });
  }

  if (/SetWindowsHookEx|RegisterHotKey|powercfg|HIGH_PRIORITY_CLASS/i.test(text)) {
    findings.push({
      id: "fp-hooks-priority",
      scanner: "device-footprint",
      severity: "medium",
      title: "Системные хуки / высокий приоритет",
      detail: "Есть API хуков клавиатуры или повышения приоритета процесса.",
      category: "performance",
      meaning: "Может тормозить систему или перехватывать ввод.",
      action: "Оставьте только если это заявленная функция (макросы и т.п.).",
    });
  }

  if (/while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)/i.test(text) && /setInterval\s*\(\s*[^,]+,\s*[0-5]\s*\)/i.test(text)) {
    findings.push({
      id: "fp-tight-loop",
      scanner: "device-footprint",
      severity: "low",
      title: "Признаки плотных циклов / частых таймеров",
      detail: "В JS/строках есть tight loop или setInterval с очень маленьким delay.",
      category: "performance",
      meaning: "Фоновые циклы греют CPU даже в простое.",
      action: "Снизьте частоту polling; используйте event-driven подход.",
    });
  }

  if (entropy >= 7.9 && sizeMb >= 50) {
    findings.push({
      id: "fp-packed-heavy",
      scanner: "device-footprint",
      severity: "low",
      title: "Плотно упакованный крупный бинарь",
      detail: `Entropy ${entropy.toFixed(2)} при размере ${sizeMb.toFixed(0)} МБ.`,
      category: "performance",
      meaning: "Распаковка при установке/запуске даёт пик CPU и диска.",
      action: "Нормально для installer; убедитесь, что нет лишнего double-pack.",
    });
  }

  // Autostart hints
  if (/CurrentVersion\\\\Run|LaunchAgents|launchd|schtasks|StartupApproved/i.test(text)) {
    findings.push({
      id: "fp-autostart",
      scanner: "device-footprint",
      severity: "medium",
      title: "Автозапуск со стартом системы",
      detail: "Есть строки реестра/LaunchAgents/schtasks для автозапуска.",
      category: "policy",
      meaning: "Приложение будет жить в фоне и тратить ресурсы без явного старта.",
      action: "Делайте автозапуск opt-in и объясняйте пользователю.",
    });
  }

  void fileName;
  return {
    scanner: "device-footprint",
    displayName: "Device Footprint",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? `Footprint OK · ${sizeMb.toFixed(1)} МБ.`
        : `Влияние на устройство: ${findings.length} сигнал(ов) · ${sizeMb.toFixed(0)} МБ.`,
    findings,
    meta: {
      pillar: "device",
      sizeMb: Number(sizeMb.toFixed(2)),
      entropy: Number(entropy.toFixed(3)),
    },
  };
}

/** Integrity / authenticity heuristics (signature presence, PE authenticity cues). */
export async function runIntegrityAuditor(
  buf: Buffer,
  fileName: string,
): Promise<EngineResult> {
  const started = Date.now();
  const findings: ThreatFinding[] = [];
  const pe = inspectPe(buf);
  const text = extractSearchText(buf, 2_500_000);
  const strings = collectAsciiStrings(buf, { minLen: 8, maxStrings: 2500 });
  const ext = path.extname(fileName).toLowerCase();

  if (/\.(exe|dll|msi|sys)$/i.test(ext) || pe.isPe) {
    // Authenticode directory often referenced; heuristic: look for signature-related strings
    const hasSigCue =
      /SignerSign|WinVerifyTrust|digicert|sectigo|globalsign|verisign|Certum|Authenticode|signtool/i.test(
        text,
      ) || strings.some((s) => /DigiCert|Sectigo|GlobalSign|Certum/i.test(s));

    // PE attribute certificate table at data directory index 4 — rough parse
    let hasCertTable = false;
    if (pe.isPe && buf.length > 0x100) {
      try {
        const peOffset = buf.readUInt32LE(0x3c);
        const optMagic = buf.readUInt16LE(peOffset + 24);
        const ddOffset =
          optMagic === 0x20b
            ? peOffset + 24 + 112 // PE32+
            : peOffset + 24 + 96; // PE32
        if (ddOffset + 40 < buf.length) {
          const certVa = buf.readUInt32LE(ddOffset + 32);
          const certSize = buf.readUInt32LE(ddOffset + 36);
          hasCertTable = certVa > 0 && certSize > 0;
        }
      } catch {
        /* ignore parse errors */
      }
    }

    if (!hasCertTable && !hasSigCue) {
      findings.push({
        id: "int-unsigned",
        scanner: "integrity",
        severity: "medium",
        title: "Нет признаков Authenticode-подписи",
        detail: "PE не содержит очевидной certificate table / signer metadata.",
        category: "integrity",
        meaning:
          "Неподписанные .exe Windows SmartScreen ругает, проще подменить файл по пути доставки.",
        action: "Подпишите сборку code signing сертификатом перед массовым релизом.",
      });
    } else if (hasCertTable) {
      // positive — no finding
    }

    if (/\.(pdf|jpg|png|txt|docx)\.exe$/i.test(fileName)) {
      findings.push({
        id: "int-double-ext",
        scanner: "integrity",
        severity: "critical",
        title: "Двойное расширение (маска документа)",
        detail: `Имя файла ${fileName} маскирует executable под документ.`,
        category: "trojan",
        meaning: "Классический социальный инженерный трюк.",
        action: "Переименуйте честно (Setup.exe) — иначе стор заблокирует.",
      });
    }
  }

  // Source map / debug leftovers
  if (/\.map"|\.pdb|DEBUG_MODE|localhost:\d{2,5}/i.test(text) && /production|app\.asar/i.test(text)) {
    findings.push({
      id: "int-debug-leftovers",
      scanner: "integrity",
      severity: "low",
      title: "Отладочные артефакты в релизе",
      detail: "Встречаются source map / pdb / localhost debug-строки.",
      category: "integrity",
      meaning: "Упрощает реверс и указывает на «сырую» production-сборку.",
      action: "Вычистите source maps/pdb из production и закройте debug endpoints.",
    });
  }

  if (!pe.isPe && !/\.(exe|dll|msi)$/i.test(ext)) {
    if (findings.length === 0) {
      return {
        scanner: "integrity",
        displayName: "Integrity Auditor",
        verdict: "skipped",
        score: 100,
        durationMs: Date.now() - started,
        summary: "Не Windows PE — проверка подписи пропущена.",
        findings: [],
        meta: { skipped: true, pillar: "integrity" },
      };
    }
  }

  return {
    scanner: "integrity",
    displayName: "Integrity Auditor",
    verdict: verdictFromFindings(findings),
    score: scoreFromFindings(findings),
    durationMs: Date.now() - started,
    summary:
      findings.length === 0
        ? "Целостность: явных проблем подписи/маскировки не видно."
        : `Integrity: ${findings.length} замечание(й).`,
    findings,
    meta: { pillar: "integrity", isPe: pe.isPe },
  };
}
