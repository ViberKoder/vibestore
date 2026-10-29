"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import type { StoreApp } from "@/lib/types";
import { formatBytes } from "@/lib/format";
import { AppIcon } from "./app-icon";

export function AppEditForm({ app }: { app: StoreApp }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [clearIcon, setClearIcon] = useState(false);
  const [removeShots, setRemoveShots] = useState<Set<string>>(new Set());
  const [iconPreview, setIconPreview] = useState<string | null>(null);

  const featuresText = useMemo(
    () =>
      (app.features ?? [])
        .map((f) => (f.detail ? `${f.title} | ${f.detail}` : f.title))
        .join("\n"),
    [app.features],
  );

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setOk(null);
    const form = e.currentTarget;
    const data = new FormData(form);
    if (clearIcon) data.set("clearIcon", "1");
    if (removeShots.size) {
      data.set("removeScreenshotIds", [...removeShots].join(","));
    }

    try {
      const res = await fetch(`/api/apps/${app.id}`, {
        method: "PATCH",
        body: data,
      });
      const json = (await res.json()) as {
        error?: string;
        rescan?: boolean;
        app?: { slug: string };
      };
      if (!res.ok) {
        setError(json.error ?? "Не удалось сохранить");
        setBusy(false);
        return;
      }
      setOk("Сохранено");
      setBusy(false);
      if (json.rescan && json.app?.slug) {
        router.push(`/apps/${json.app.slug}?scanning=1`);
        return;
      }
      router.push(`/apps/${json.app?.slug ?? app.slug}`);
      router.refresh();
    } catch {
      setError("Сеть недоступна");
      setBusy(false);
    }
  }

  async function onDelete() {
    if (
      !window.confirm(
        `Удалить «${app.name}» безвозвратно? Файл сборки и медиа тоже будут удалены.`,
      )
    ) {
      return;
    }
    setDeleting(true);
    setError(null);
    try {
      const res = await fetch(`/api/apps/${app.id}`, { method: "DELETE" });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) {
        setError(json.error ?? "Не удалось удалить");
        setDeleting(false);
        return;
      }
      router.push("/dashboard");
      router.refresh();
    } catch {
      setError("Сеть недоступна");
      setDeleting(false);
    }
  }

  const visibleShots = (app.screenshots ?? []).filter(
    (s) => !removeShots.has(s.id),
  );

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      <section className="space-y-3">
        <h2 className="text-[15px] font-semibold tracking-[-0.02em]">
          Аватарка
        </h2>
        <div className="flex flex-wrap items-center gap-4">
          {iconPreview ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={iconPreview}
              alt=""
              className="app-icon h-[72px] w-[72px] object-cover"
            />
          ) : clearIcon ? (
            <AppIcon app={{ ...app, iconUrl: undefined }} size="md" />
          ) : (
            <AppIcon app={app} size="md" />
          )}
          <div className="min-w-0 flex-1 space-y-2">
            <input
              type="file"
              name="icon"
              accept="image/png,image/jpeg,image/webp,image/gif"
              disabled={busy || deleting}
              onChange={(e) => {
                const f = e.target.files?.[0];
                setClearIcon(false);
                if (f) setIconPreview(URL.createObjectURL(f));
                else setIconPreview(null);
              }}
              className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
            />
            {(app.iconUrl || iconPreview) && !clearIcon && (
              <button
                type="button"
                className="text-[12px] font-medium text-ink-3 hover:text-red-ink"
                onClick={() => {
                  setClearIcon(true);
                  setIconPreview(null);
                  const input = document.querySelector<HTMLInputElement>(
                    'input[name="icon"]',
                  );
                  if (input) input.value = "";
                }}
              >
                Убрать аватарку
              </button>
            )}
          </div>
        </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2">
        <Field
          label="Название"
          name="name"
          defaultValue={app.name}
          required
          disabled={busy || deleting}
        />
        <Field
          label="Версия"
          name="version"
          defaultValue={app.version}
          required
          disabled={busy || deleting}
        />
        <Field
          label="Слоган"
          name="tagline"
          defaultValue={app.tagline}
          required
          disabled={busy || deleting}
        />
        <Field
          label="Категория"
          name="category"
          defaultValue={app.category}
          disabled={busy || deleting}
        />
        <Field
          label="Разработчик"
          name="developerName"
          defaultValue={app.developerName}
          required
          disabled={busy || deleting}
        />
        <Field
          label="Email"
          name="developerEmail"
          type="email"
          defaultValue={app.developerEmail ?? ""}
          disabled={busy || deleting}
        />
        <label className="block space-y-2">
          <span className="text-[13px] font-semibold text-ink">Тип</span>
          <select
            name="kind"
            defaultValue={app.kind}
            disabled={busy || deleting}
            className="field-input"
          >
            <option value="desktop">Desktop</option>
            <option value="web">Web</option>
            <option value="cli">CLI</option>
            <option value="mobile">Mobile</option>
            <option value="other">Other</option>
          </select>
        </label>
        <Field
          label="Сайт"
          name="homepage"
          defaultValue={app.homepage ?? ""}
          disabled={busy || deleting}
        />
      </div>

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">Описание</span>
        <textarea
          name="description"
          required
          rows={5}
          defaultValue={app.description}
          disabled={busy || deleting}
          className="field-input min-h-[120px] resize-y"
        />
      </label>

      <Field
        label="Теги (через запятую)"
        name="tags"
        defaultValue={app.tags.join(", ")}
        disabled={busy || deleting}
      />

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">
          Возможности (по строке)
        </span>
        <textarea
          name="features"
          rows={4}
          defaultValue={featuresText}
          disabled={busy || deleting}
          className="field-input min-h-[96px] resize-y font-mono text-[13px]"
          placeholder="Заголовок | детали"
        />
      </label>

      <section className="space-y-3">
        <h2 className="text-[15px] font-semibold tracking-[-0.02em]">
          Скриншоты
        </h2>
        {visibleShots.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {visibleShots.map((s) => (
              <div key={s.id} className="relative">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={s.url}
                  alt={s.caption ?? ""}
                  className="h-20 w-28 rounded-xl object-cover"
                />
                <button
                  type="button"
                  className="absolute right-1 top-1 rounded-full bg-black/60 px-1.5 text-[11px] font-bold text-white"
                  onClick={() =>
                    setRemoveShots((prev) => new Set(prev).add(s.id))
                  }
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        )}
        <input
          type="file"
          name="screenshots"
          accept="image/png,image/jpeg,image/webp,image/gif"
          multiple
          disabled={busy || deleting}
          className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
        />
      </section>

      <section className="space-y-2">
        <h2 className="text-[15px] font-semibold tracking-[-0.02em]">
          Новая сборка (опционально)
        </h2>
        <p className="text-[12px] text-ink-3">
          Текущий файл: {app.fileName} · {formatBytes(app.fileSize)}. Загрузка
          новой версии запустит полный рескан.
        </p>
        <input
          type="file"
          name="file"
          disabled={busy || deleting}
          className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
        />
      </section>

      {error && (
        <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
          {error}
        </p>
      )}
      {ok && (
        <p className="rounded-2xl bg-green-soft px-4 py-3 text-[13px] text-green-ink">
          {ok}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={busy || deleting}
          className="btn-primary"
        >
          {busy ? "Сохраняем…" : "Сохранить изменения"}
        </button>
        <button
          type="button"
          onClick={() => router.push(`/apps/${app.slug}`)}
          disabled={busy || deleting}
          className="btn-secondary"
        >
          Отмена
        </button>
        <button
          type="button"
          onClick={onDelete}
          disabled={busy || deleting}
          className="ml-auto inline-flex h-11 items-center rounded-full bg-red-soft px-5 text-[14px] font-semibold text-red-ink transition hover:opacity-90 disabled:opacity-50"
        >
          {deleting ? "Удаляем…" : "Удалить приложение"}
        </button>
      </div>
    </form>
  );
}

function Field({
  label,
  name,
  required,
  placeholder,
  type = "text",
  disabled,
  defaultValue,
}: {
  label: string;
  name: string;
  required?: boolean;
  placeholder?: string;
  type?: string;
  disabled?: boolean;
  defaultValue?: string;
}) {
  return (
    <label className="block space-y-2">
      <span className="text-[13px] font-semibold text-ink">{label}</span>
      <input
        name={name}
        type={type}
        required={required}
        placeholder={placeholder}
        disabled={disabled}
        defaultValue={defaultValue}
        className="field-input"
      />
    </label>
  );
}
