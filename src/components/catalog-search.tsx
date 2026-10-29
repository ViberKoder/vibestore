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
    <form onSubmit={submit} className="flex w-full max-w-xl gap-2">
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Поиск: notes, exe, windows…"
        className="h-12 flex-1 rounded-xl border border-ink/10 bg-white/70 px-4 text-sm outline-none ring-teal/30 focus:ring-2"
      />
      <button
        type="submit"
        disabled={pending}
        className="h-12 rounded-xl bg-ink px-5 text-sm font-semibold text-paper transition hover:bg-teal-deep"
      >
        Найти
      </button>
    </form>
  );
}
