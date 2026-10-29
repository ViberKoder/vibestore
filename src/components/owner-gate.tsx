"use client";

import { useEffect, useState } from "react";

export function OwnerGate({
  appId,
  appName,
  children,
}: {
  appId: string;
  appName: string;
  children: React.ReactNode;
}) {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const ctrl = new AbortController();
    fetch(`/api/apps/${appId}/unlock`, {
      credentials: "include",
      signal: ctrl.signal,
    })
      .then((res) => res.json())
      .then((json: { unlocked?: boolean }) => {
        setUnlocked(Boolean(json.unlocked));
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setUnlocked(false);
      });
    return () => ctrl.abort();
  }, [appId]);

  async function unlock(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/apps/${appId}/unlock`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ownerKey: key.trim() }),
      });
      const json = (await res.json()) as { error?: string; unlocked?: boolean };
      if (!res.ok) {
        setError(json.error ?? "Не удалось разблокировать");
        setBusy(false);
        return;
      }
      setUnlocked(true);
      setBusy(false);
    } catch {
      setError("Сеть недоступна");
      setBusy(false);
    }
  }

  async function lock() {
    await fetch(`/api/apps/${appId}/unlock`, {
      method: "DELETE",
      credentials: "include",
    }).catch(() => undefined);
    setUnlocked(false);
    setKey("");
  }

  if (unlocked === null) {
    return (
      <p className="text-[14px] text-ink-2">Проверяем доступ владельца…</p>
    );
  }

  if (!unlocked) {
    return (
      <form onSubmit={unlock} className="space-y-4">
        <div>
          <h2 className="text-[18px] font-bold tracking-[-0.02em]">
            Ключ владельца
          </h2>
          <p className="mt-2 text-[14px] leading-relaxed text-ink-2">
            Редактировать «{appName}» может только тот, у кого есть ключ,
            выданный при публикации. Без ключа изменения недоступны.
          </p>
        </div>
        <label className="block space-y-2">
          <span className="text-[13px] font-semibold text-ink">Owner key</span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="vsk_…"
            className="field-input font-mono text-[13px]"
            required
          />
        </label>
        {error && (
          <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy} className="btn-primary">
          {busy ? "Проверяем…" : "Разблокировать"}
        </button>
      </form>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-green-soft px-3.5 py-2.5 text-[13px] text-green-ink">
        <span>Доступ владельца активен для этой сессии.</span>
        <button
          type="button"
          onClick={lock}
          className="font-semibold underline-offset-2 hover:underline"
        >
          Выйти
        </button>
      </div>
      {children}
    </div>
  );
}
