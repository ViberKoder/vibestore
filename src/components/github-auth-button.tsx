"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useT } from "@/lib/i18n/client";

type Me = {
  configured: boolean;
  user: { login: string; avatarUrl: string | null } | null;
};

/** Sign-in state in the header. Renders nothing when GitHub login is not configured. */
export function GithubAuthButton() {
  const t = useT();
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    let alive = true;
    fetch("/api/auth/me", { cache: "no-store" })
      .then((r) => r.json())
      .then((j: Me) => alive && setMe(j))
      .catch(() => alive && setMe({ configured: false, user: null }));
    return () => {
      alive = false;
    };
  }, []);

  if (!me || !me.configured) return null;

  if (!me.user) {
    return (
      <a href="/api/auth/github" className="btn-secondary !h-9 !min-w-0 !px-3 !text-[13px]">
        {t("Sign in with GitHub")}
      </a>
    );
  }

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/");
    router.refresh();
  }

  return (
    <div className="flex items-center gap-1.5">
      <Link href="/import" className="hidden text-[13px] font-medium text-ink-2 hover:text-ink sm:inline">
        {t("Import")}
      </Link>
      {me.user.avatarUrl && (
        // eslint-disable-next-line @next/next/no-img-element
        <img src={me.user.avatarUrl} alt="" width={26} height={26} className="h-[26px] w-[26px] rounded-full" />
      )}
      <span className="max-w-[120px] truncate text-[13px] font-medium text-ink">@{me.user.login}</span>
      <button type="button" onClick={signOut} className="text-[12px] text-ink-3 hover:text-ink">
        {t("Sign out")}
      </button>
    </div>
  );
}
