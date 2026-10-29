/** Known malware / stealer / trojan string signatures for VibeGuard. */
export const STEALER_PATTERNS: Array<{
  id: string;
  title: string;
  pattern: RegExp;
  severity: "medium" | "high" | "critical";
}> = [
  {
    id: "discord-webhook",
    title: "Discord webhook exfiltration",
    pattern: /discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/i,
    severity: "critical",
  },
  {
    id: "telegram-bot",
    title: "Telegram bot token sink",
    pattern: /api\.telegram\.org\/bot\d+:[\w-]+/i,
    severity: "critical",
  },
  {
    id: "browser-cookies",
    title: "Browser cookie theft path",
    pattern:
      /(?:Local Storage|Login Data|Cookies|Web Data).*?(?:Chrome|Brave|Edge|Opera|Firefox)/i,
    severity: "high",
  },
  {
    id: "wallet-paths",
    title: "Crypto wallet path harvest",
    pattern:
      /(?:Electrum|Exodus|Atomic|MetaMask|Phantom|Solflare).*?(?:wallet|keystore|seed)/i,
    severity: "critical",
  },
  {
    id: "keylogger",
    title: "Keylogger API usage",
    pattern: /SetWindowsHookEx[AW]?|GetAsyncKeyState|keylog/i,
    severity: "high",
  },
  {
    id: "credential-dump",
    title: "Credential dump indicator",
    pattern: /mimikatz|sekurlsa|lsass\.exe|procdump/i,
    severity: "critical",
  },
  {
    id: "powershell-download",
    title: "PowerShell download cradle",
    pattern:
      /powershell.*(?:IEX|Invoke-Expression).*?(?:DownloadString|DownloadFile)/i,
    severity: "high",
  },
  {
    id: "pastebin-c2",
    title: "Pastebin / raw C2 fetch",
    pattern: /pastebin\.com\/raw\/|githubusercontent\.com\/.*\/raw\//i,
    severity: "medium",
  },
];

export const VIRUS_NAME_HINTS = [
  "trojan",
  "stealer",
  "ransomware",
  "backdoor",
  "worm",
  "spyware",
  "adware",
  "rootkit",
  "coinminer",
  "dropper",
];

export const SUSPICIOUS_EXTS = [
  ".scr",
  ".pif",
  ".cpl",
  ".hta",
  ".vbs",
  ".js",
  ".jse",
  ".wsf",
  ".bat",
  ".cmd",
  ".ps1",
];

export const SAFE_DEMO_MARKERS = [
  "vibestore-clean-fixture",
  "hello vibe store",
  "demo safe application",
];
