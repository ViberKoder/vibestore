"use client";

import { useT } from "@/lib/i18n/client";

const items = [
  { name: "VirusTotal", hint: "70+ vendors" },
  { name: "ClamAV", hint: "open-source AV" },
  { name: "ClamWin", hint: "Windows DB" },
  { name: "VibeGuard", hint: "our rules" },
];

export function TrustStrip() {
  const t = useT();
  return (
    <div className="surface-card px-5 py-5 md:px-7">
      <p className="text-[12px] font-semibold uppercase tracking-[0.14em] text-ink-3">
        {t("We check every build")}
      </p>
      <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4">
        {items.map((item) => (
          <div key={item.name} className="min-w-0">
            <div className="text-[15px] font-semibold tracking-[-0.02em] text-ink">
              {item.name}
            </div>
            <div className="mt-0.5 text-[12px] text-ink-2">{t(item.hint)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
