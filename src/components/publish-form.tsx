"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

export function PublishForm() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "uploading" | "scanning">("idle");

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const form = e.currentTarget;
    const data = new FormData(form);
    const file = data.get("file");
    if (!(file instanceof File) || file.size === 0) {
      setError("Прикрепите файл приложения (.exe, .zip, .html и др.)");
      return;
    }

    setPhase("uploading");
    startTransition(async () => {
      try {
        setPhase("scanning");
        const res = await fetch("/api/publish", {
          method: "POST",
          body: data,
        });
        const json = (await res.json()) as {
          app?: { slug: string };
          error?: string;
        };
        if (!res.ok) {
          setError(json.error ?? "Ошибка публикации");
          setPhase("idle");
          return;
        }
        if (json.app?.slug) {
          router.push(`/apps/${json.app.slug}`);
          return;
        }
        setError("Неожиданный ответ сервера");
        setPhase("idle");
      } catch {
        setError("Сеть недоступна или сервер не ответил");
        setPhase("idle");
      }
    });
  }

  return (
    <form onSubmit={onSubmit} className="space-y-5">
      <Field label="Название" name="name" required placeholder="ClipForge" />
      <Field
        label="Короткий слоган"
        name="tagline"
        required
        placeholder="Одно предложение о продукте"
      />
      <label className="block space-y-1.5">
        <span className="text-sm font-medium text-ink">Описание</span>
        <textarea
          name="description"
          required
          rows={4}
          className="w-full rounded-xl border border-ink/10 bg-white/70 px-3 py-2.5 text-sm outline-none ring-teal/30 focus:ring-2"
          placeholder="Что делает приложение и для кого"
        />
      </label>
      <div className="grid gap-4 md:grid-cols-2">
        <Field
          label="Разработчик"
          name="developerName"
          required
          placeholder="Ваше имя или студия"
        />
        <Field
          label="Email"
          name="developerEmail"
          type="email"
          placeholder="dev@example.com"
        />
        <Field label="Версия" name="version" placeholder="0.1.0" />
        <Field label="Категория" name="category" placeholder="Utilities" />
        <label className="block space-y-1.5">
          <span className="text-sm font-medium text-ink">Тип</span>
          <select
            name="kind"
            className="w-full rounded-xl border border-ink/10 bg-white/70 px-3 py-2.5 text-sm outline-none ring-teal/30 focus:ring-2"
            defaultValue="desktop"
          >
            <option value="desktop">Desktop (.exe и др.)</option>
            <option value="web">Web / сайт</option>
            <option value="cli">CLI</option>
            <option value="mobile">Mobile</option>
            <option value="other">Other</option>
          </select>
        </label>
        <Field
          label="Сайт"
          name="homepage"
          placeholder="https://"
        />
      </div>
      <Field
        label="Теги (через запятую)"
        name="tags"
        placeholder="windows, productivity, vibe"
      />
      <label className="block space-y-1.5">
        <span className="text-sm font-medium text-ink">Файл сборки</span>
        <input
          type="file"
          name="file"
          required
          className="block w-full text-sm text-ink-soft file:mr-3 file:rounded-lg file:border-0 file:bg-teal file:px-3 file:py-2 file:text-sm file:font-semibold file:text-white hover:file:bg-teal-deep"
        />
        <span className="text-xs text-ink-soft">
          До 64 МБ · exe, msi, zip, dmg, html, apk, jar и другие
        </span>
      </label>

      {error && (
        <p className="rounded-xl bg-coral/10 px-3 py-2 text-sm text-coral">
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending || phase !== "idle"}
        className="inline-flex h-12 items-center justify-center rounded-xl bg-teal px-6 text-sm font-semibold text-white transition hover:bg-teal-deep disabled:cursor-wait disabled:opacity-70"
      >
        {phase === "uploading" || phase === "scanning" || pending
          ? "Сканируем VirusTotal · ClamAV · VibeGuard…"
          : "Загрузить и просканировать"}
      </button>
    </form>
  );
}

function Field({
  label,
  name,
  required,
  placeholder,
  type = "text",
}: {
  label: string;
  name: string;
  required?: boolean;
  placeholder?: string;
  type?: string;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-sm font-medium text-ink">{label}</span>
      <input
        name={name}
        type={type}
        required={required}
        placeholder={placeholder}
        className="w-full rounded-xl border border-ink/10 bg-white/70 px-3 py-2.5 text-sm outline-none ring-teal/30 focus:ring-2"
      />
    </label>
  );
}
