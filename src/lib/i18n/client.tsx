"use client";

import { createContext, useCallback, useContext, useMemo } from "react";
import { useRouter } from "next/navigation";
import { LOCALE_COOKIE, makeT, type Locale } from "./core";

type I18nValue = { locale: Locale; t: (text: string) => string };

const Ctx = createContext<I18nValue>({ locale: "en", t: (s) => s });

export function LocaleProvider({
  locale,
  children,
}: {
  locale: Locale;
  children: React.ReactNode;
}) {
  const value = useMemo(() => ({ locale, t: makeT(locale) }), [locale]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** `const t = useT(); t("Catalog")` — returns the translation for the current locale. */
export function useT() {
  return useContext(Ctx).t;
}

export function useLocale() {
  return useContext(Ctx).locale;
}

export function LanguageSwitcher() {
  const { locale } = useContext(Ctx);
  const router = useRouter();

  const choose = useCallback(
    (next: Locale) => {
      if (next === locale) return;
      document.cookie = `${LOCALE_COOKIE}=${next}; Path=/; Max-Age=31536000; SameSite=Lax`;
      router.refresh();
    },
    [locale, router],
  );

  return (
    <div
      role="group"
      aria-label="Language"
      className="flex overflow-hidden rounded-full bg-[color-mix(in_srgb,var(--ink)_6%,transparent)] text-[12px] font-semibold"
    >
      {(["en", "ru"] as const).map((code) => (
        <button
          key={code}
          type="button"
          onClick={() => choose(code)}
          aria-pressed={locale === code}
          className={`h-9 px-2.5 transition ${
            locale === code
              ? "bg-[var(--bg)] text-ink shadow-sm"
              : "text-ink-2 hover:text-ink"
          }`}
        >
          {code.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
