export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

/** Locale-aware thousands separators: "en" → 1,234 / "ru" → 1 234. */
export function formatNumber(n: number, locale: string = "en"): string {
  return new Intl.NumberFormat(locale === "ru" ? "ru-RU" : "en-US").format(n);
}
