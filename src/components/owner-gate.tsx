"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { fill } from "@/lib/i18n/core";
import { useT } from "@/lib/i18n/client";

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
  const t = useT();
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
        setError(json.error ?? t("Could not link the app"));
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
      setError(t("Network unavailable"));
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
        setError(json.error ?? t("Could not restore access"));
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
      setError(t("Network unavailable"));
      setBusy(false);
    }
  }

  if (!status) {
    return (
      <p className="text-[14px] text-ink-2">{t("Checking access…")}</p>
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
            {t("Link management")}
          </h2>
          <p className="mt-2 text-[14px] leading-relaxed text-ink-2">
            {fill(
              t(
                "«{name}» is not linked to this browser yet. If this is your app, link it here.",
              ),
              { name: appName },
            )}
          </p>
        </div>
        {error && (
          <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
            {t(error)}
          </p>
        )}
        <button
          type="button"
          onClick={claim}
          disabled={busy}
          className="btn-primary"
        >
          {busy ? t("Linking…") : t("This is my app")}
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={restore} className="space-y-4">
      <div>
        <h2 className="text-[18px] font-bold tracking-[-0.02em]">
          {t("Restore access")}
        </h2>
        <p className="mt-2 text-[14px] leading-relaxed text-ink-2">
          {fill(
            t(
              "The cookie may have been lost after the tunnel address changed or the browser was cleared. Enter the developer name from the «{name}» app page to link management to this browser again.",
            ),
            { name: appName },
          )}
        </p>
      </div>
      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">
          {t("Developer name")}
        </span>
        <input
          value={nameInput}
          onChange={(e) => setNameInput(e.target.value)}
          className="field-input"
          placeholder={t("As on the app page")}
          required
        />
      </label>
      {error && (
        <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
          {t(error)}
        </p>
      )}
      <button type="submit" disabled={busy} className="btn-primary">
        {busy ? t("Restoring…") : t("Restore on this browser")}
      </button>
    </form>
  );
}
