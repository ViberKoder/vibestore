"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState, useTransition } from "react";

export function CatalogSearch({ initialQ = "" }: { initialQ?: string }) {
  const router = useRouter();
  const params = useSearchParams();
  const [q, setQ] = useState(initialQ);
  const [pending, startTransition] = useTransition();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const next = new URLSearchParams(params.toString());
    if (q.trim()) next.set("q", q.trim());
    else next.delete("q");
    startTransition(() => {
      router.push(`/?${next.toString()}#catalog`);
    });
  }

  return (
    <form onSubmit={submit} className="relative w-full max-w-md">
      <svg
        className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        aria-hidden
      >
        <circle cx="11" cy="11" r="7" />
        <path d="M20 20l-3.5-3.5" strokeLinecap="round" />
      </svg>
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Поиск приложений"
        className="h-11 w-full rounded-full border-0 bg-black/[0.045] pl-10 pr-4 text-[14px] text-ink outline-none ring-blue/30 placeholder:text-ink-3 focus:bg-white focus:ring-2"
      />
      <button type="submit" className="sr-only" disabled={pending}>
        Найти
      </button>
    </form>
  );
}
