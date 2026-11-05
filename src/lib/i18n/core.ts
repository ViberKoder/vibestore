import { RU, RU_PATTERNS } from "./ru";

/**
 * UI language. English is the default and the source language of the code:
 * every string in the source is English, and `ru` holds translations keyed by
 * that exact English text. Dynamic messages (counts, file names) are matched
 * with RU_PATTERNS.
 */
export type Locale = "en" | "ru";

export const LOCALES: readonly Locale[] = ["en", "ru"];
export const DEFAULT_LOCALE: Locale = "en";
export const LOCALE_COOKIE = "vibe_lang";

export function parseLocale(value: string | null | undefined): Locale {
  return value === "ru" ? "ru" : DEFAULT_LOCALE;
}

export function translate(text: string, locale: Locale): string {
  if (locale === "en" || !text) return text;
  const exact = RU[text];
  if (exact !== undefined) return exact;
  for (const [pattern, template] of RU_PATTERNS) {
    if (pattern.test(text)) return text.replace(pattern, template);
  }
  return text;
}

export type Translator = (text: string) => string;

export function makeT(locale: Locale): Translator {
  return (text) => translate(text, locale);
}

/** Substitutes `{name}` placeholders after translation: fill(t("Hi {name}"), { name }). */
export function fill(text: string, vars: Record<string, string | number>): string {
  return text.replace(/\{(\w+)\}/g, (match, key: string) =>
    key in vars ? String(vars[key]) : match,
  );
}
