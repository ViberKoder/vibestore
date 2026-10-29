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

  const busy = pending || phase !== "idle";

  return (
    <form onSubmit={onSubmit} className="space-y-5">
      <Field label="Название" name="name" required placeholder="ClipForge" />
      <Field
        label="Короткий слоган"
        name="tagline"
        required
        placeholder="Одно предложение о продукте"
      />
      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">Описание</span>
        <textarea
          name="description"
          required
          rows={4}
          className="field-input min-h-[110px] resize-y"
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
        <label className="block space-y-2">
          <span className="text-[13px] font-semibold text-ink">Тип</span>
          <select name="kind" className="field-input" defaultValue="desktop">
            <option value="desktop">Desktop (.exe и др.)</option>
            <option value="web">Web / сайт</option>
            <option value="cli">CLI</option>
            <option value="mobile">Mobile</option>
            <option value="other">Other</option>
          </select>
        </label>
        <Field label="Сайт" name="homepage" placeholder="https://" />
      </div>
      <Field
        label="Теги (через запятую)"
        name="tags"
        placeholder="windows, productivity, vibe"
      />

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">Файл сборки</span>
        <div className="rounded-2xl border border-dashed border-black/15 bg-bg px-4 py-6">
          <input
            type="file"
            name="file"
            required
            className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
          />
          <p className="mt-3 text-[12px] text-ink-3">
            До 64 МБ · exe, msi, zip, dmg, html, apk, jar и другие
          </p>
        </div>
      </label>

      {error && (
        <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
          {error}
        </p>
      )}

      <button type="submit" disabled={busy} className="btn-primary w-full sm:w-auto">
        {busy
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
    <label className="block space-y-2">
      <span className="text-[13px] font-semibold text-ink">{label}</span>
      <input
        name={name}
        type={type}
        required={required}
        placeholder={placeholder}
        className="field-input"
      />
    </label>
  );
}
