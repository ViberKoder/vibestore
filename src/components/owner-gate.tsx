"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

type Status = {
  isOwner: boolean;
  canClaim: boolean;
  canRestore: boolean;
  hasOwner: boolean;
};

export function OwnerGate({
  appId,
  appName,
  developerName,
  children,
}: {
  appId: string;
  appName: string;
  developerName?: string;
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [nameInput, setNameInput] = useState(developerName ?? "");

  useEffect(() => {
    const ctrl = new AbortController();
    fetch(`/api/apps/${appId}/unlock`, {
      credentials: "include",
      signal: ctrl.signal,
    })
      .then((res) => res.json())
      .then((json: Status & { error?: string }) => {
        setStatus({
          isOwner: Boolean(json.isOwner),
          canClaim: Boolean(json.canClaim),
          canRestore: Boolean(json.canRestore),
          hasOwner: Boolean(json.hasOwner),
        });
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setStatus({
          isOwner: false,
          canClaim: false,
          canRestore: true,
          hasOwner: true,
        });
      });
    return () => ctrl.abort();
  }, [appId]);

  async function claim() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/apps/${appId}/unlock`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) {
        setError(json.error ?? "Не удалось привязать");
        setBusy(false);
        return;
      }
      setStatus({
        isOwner: true,
        canClaim: false,
        canRestore: false,
        hasOwner: true,
      });
      setBusy(false);
      router.refresh();
    } catch {
      setError("Сеть недоступна");
      setBusy(false);
    }
  }

  async function restore(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/apps/${appId}/unlock`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reclaim: true,
          developerName: nameInput.trim(),
        }),
      });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) {
        setError(json.error ?? "Не удалось восстановить");
        setBusy(false);
        return;
      }
      setStatus({
        isOwner: true,
        canClaim: false,
        canRestore: false,
        hasOwner: true,
      });
      setBusy(false);
      router.refresh();
    } catch {
      setError("Сеть недоступна");
      setBusy(false);
    }
  }

  if (!status) {
    return (
      <p className="text-[14px] text-ink-2">Проверяем доступ…</p>
    );
  }

  if (status.isOwner) {
    return <>{children}</>;
  }

  if (status.canClaim) {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-[18px] font-bold tracking-[-0.02em]">
            Привязать управление
          </h2>
          <p className="mt-2 text-[14px] leading-relaxed text-ink-2">
            «{appName}» ещё не привязано к браузеру. Если это ваше приложение —
            привяжите его сюда.
          </p>
        </div>
        {error && (
          <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
            {error}
          </p>
        )}
        <button
          type="button"
          onClick={claim}
          disabled={busy}
          className="btn-primary"
        >
          {busy ? "Привязываем…" : "Это моё приложение"}
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={restore} className="space-y-4">
      <div>
        <h2 className="text-[18px] font-bold tracking-[-0.02em]">
          Восстановить доступ
        </h2>
        <p className="mt-2 text-[14px] leading-relaxed text-ink-2">
          Cookie мог слететь после смены адреса туннеля или очистки браузера.
          Введите имя разработчика с карточки «{appName}», чтобы снова привязать
          управление к этому браузеру.
        </p>
      </div>
      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">
          Имя разработчика
        </span>
        <input
          value={nameInput}
          onChange={(e) => setNameInput(e.target.value)}
          className="field-input"
          placeholder="Как в карточке приложения"
          required
        />
      </label>
      {error && (
        <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy} className="btn-primary">
        {busy ? "Восстанавливаем…" : "Восстановить на этом браузере"}
      </button>
    </form>
  );
}
