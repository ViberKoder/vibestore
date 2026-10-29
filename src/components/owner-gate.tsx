"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

type Status = {
  isOwner: boolean;
  canClaim: boolean;
  hasOwner: boolean;
};

export function OwnerGate({
  appId,
  appName,
  children,
}: {
  appId: string;
  appName: string;
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
          hasOwner: Boolean(json.hasOwner),
        });
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setStatus({ isOwner: false, canClaim: false, hasOwner: true });
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
      });
      const json = (await res.json()) as { error?: string; isOwner?: boolean };
      if (!res.ok) {
        setError(json.error ?? "Не удалось привязать");
        setBusy(false);
        return;
      }
      setStatus({ isOwner: true, canClaim: false, hasOwner: true });
      setBusy(false);
      router.refresh();
    } catch {
      setError("Сеть недоступна");
      setBusy(false);
    }
  }

  if (!status) {
    return (
      <p className="text-[14px] text-ink-2">Проверяем, ваш ли это браузер…</p>
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
            «{appName}» загрузили до того, как магазин стал запоминать
            браузер. Если это ваше приложение — привяжите его к этому
            устройству. Потом править сможете только отсюда.
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
    <div className="space-y-3">
      <h2 className="text-[18px] font-bold tracking-[-0.02em]">Нет доступа</h2>
      <p className="text-[14px] leading-relaxed text-ink-2">
        Управлять «{appName}» может только браузер, с которого его загрузили.
      </p>
    </div>
  );
}
