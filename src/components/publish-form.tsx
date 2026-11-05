"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { formatBytes } from "@/lib/format";
import { useT } from "@/lib/i18n/client";
import { MAX_UPLOAD_BYTES } from "@/lib/types";

type Phase = "idle" | "uploading" | "starting_scan";

export function PublishForm() {
  const router = useRouter();
  const t = useT();
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [uploadPct, setUploadPct] = useState(0);
  const [fileLabel, setFileLabel] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const form = e.currentTarget;
    const data = new FormData(form);
    const file = data.get("file");
    if (!(file instanceof File) || file.size === 0) {
      setError(t("Attach the app file (.exe, .zip, .html, etc.)"));
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setError(
        `File is too large (max ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} MB)`,
      );
      return;
    }

    setPhase("uploading");
    setUploadPct(0);
    setFileLabel(`${file.name} · ${formatBytes(file.size)}`);

    try {
      const json = await uploadWithProgress(data, (pct) => setUploadPct(pct));
      if (json.error || !json.app?.slug) {
        setError(json.error ?? t("Publish failed"));
        setPhase("idle");
        return;
      }
      setPhase("starting_scan");
      setUploadPct(100);
      router.push(`/apps/${json.app.slug}?scanning=1`);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("Network unavailable"));
      setPhase("idle");
    }
  }

  const busy = phase !== "idle";

  return (
    <form onSubmit={onSubmit} className="space-y-5">
      <Field label="Name" name="name" required placeholder="ClipForge" />
      <Field
        label="Tagline"
        name="tagline"
        required
        placeholder="One sentence about the product"
      />
      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">{t("Description")}</span>
        <textarea
          name="description"
          required
          rows={4}
          className="field-input min-h-[110px] resize-y"
          placeholder="What the app does and who it is for"
          disabled={busy}
        />
      </label>
      <div className="grid gap-4 md:grid-cols-2">
        <Field
          label="Developer"
          name="developerName"
          required
          placeholder="Your name or studio"
          disabled={busy}
        />
        <Field
          label="Email"
          name="developerEmail"
          type="email"
          placeholder="dev@example.com"
          disabled={busy}
        />
        <Field label="Version" name="version" placeholder="0.1.0" disabled={busy} />
        <Field
          label="Category"
          name="category"
          placeholder="Utilities"
          disabled={busy}
        />
        <label className="block space-y-2">
          <span className="text-[13px] font-semibold text-ink">{t("Type")}</span>
          <select
            name="kind"
            className="field-input"
            defaultValue="desktop"
            disabled={busy}
          >
            <option value="desktop">Desktop (.exe, etc.)</option>
            <option value="web">Web / website</option>
            <option value="cli">CLI</option>
            <option value="mobile">Mobile</option>
            <option value="other">Other</option>
          </select>
        </label>
        <Field label="Website" name="homepage" placeholder="https://" disabled={busy} />
      </div>
      <Field
        label="Tags (comma-separated)"
        name="tags"
        placeholder="windows, productivity, vibe"
        disabled={busy}
      />

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">
          {t("Features (one per line)")}
        </span>
        <textarea
          name="features"
          rows={4}
          disabled={busy}
          className="field-input min-h-[96px] resize-y font-mono text-[13px]"
          placeholder={
            "Fast search | Finds files in milliseconds\nOffline mode\nDark theme | Auto-switch"
          }
        />
      </label>

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">{t("Icon")}</span>
        <div className="rounded-2xl border border-dashed border-[var(--line-strong)] bg-bg px-4 py-5">
          <input
            type="file"
            name="icon"
            accept="image/png,image/jpeg,image/webp,image/gif"
            disabled={busy}
            className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
          />
        </div>
      </label>

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">
          {t("Interface screenshots")}
        </span>
        <div className="rounded-2xl border border-dashed border-[var(--line-strong)] bg-bg px-4 py-5">
          <input
            type="file"
            name="screenshots"
            accept="image/png,image/jpeg,image/webp,image/gif"
            multiple
            disabled={busy}
            className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
          />
        </div>
      </label>

      <label className="block space-y-2">
        <span className="text-[13px] font-semibold text-ink">{t("Build file")}</span>
        <div className="rounded-2xl border border-dashed border-[var(--line-strong)] bg-bg px-4 py-6">
          <input
            type="file"
            name="file"
            required
            disabled={busy}
            onChange={(e) => {
              const f = e.target.files?.[0];
              setFileLabel(f ? `${f.name} · ${formatBytes(f.size)}` : null);
            }}
            className="block w-full text-[13px] text-ink-2 file:mr-3 file:rounded-full file:border-0 file:bg-blue-soft file:px-4 file:py-2 file:text-[13px] file:font-semibold file:text-blue"
          />
          <p className="mt-3 text-[12px] text-ink-3">
            {t("Up to")} {Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} {t("MB")}. {t("This browser will be remembered as the owner — only you will see «Manage».")}
          </p>
          {fileLabel && (
            <p className="mt-2 text-[13px] font-medium text-ink">{fileLabel}</p>
          )}
        </div>
      </label>

      {busy && (
        <div className="rounded-2xl border border-blue/20 bg-blue-soft px-4 py-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[14px] font-semibold text-ink">
              {phase === "uploading"
                ? t("Uploading the file to the server…")
                : t("Opening the scan screen…")}
            </p>
            <span className="text-[20px] font-bold tabular-nums text-blue">
              {uploadPct}%
            </span>
          </div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/70 dark:bg-white/10">
            <div
              className="h-full rounded-full bg-blue transition-all duration-300"
              style={{ width: `${uploadPct}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">
          {t(error)}
        </p>
      )}

      <button
        type="submit"
        disabled={busy}
        className="btn-primary w-full sm:w-auto"
      >
        {busy ? t("Uploading…") : t("Upload and scan")}
      </button>
    </form>
  );
}

function uploadWithProgress(
  data: FormData,
  onProgress: (pct: number) => void,
): Promise<{ app?: { slug: string; id: string }; error?: string }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/publish");
    xhr.withCredentials = true;
    xhr.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      onProgress(Math.max(1, Math.round((ev.loaded / ev.total) * 100)));
    };
    xhr.onload = () => {
      try {
        const json = JSON.parse(xhr.responseText) as {
          app?: { slug: string; id: string };
          error?: string;
        };
        if (xhr.status >= 400) {
          resolve({ error: json.error ?? `HTTP ${xhr.status}` });
          return;
        }
        resolve(json);
      } catch {
        reject(new Error("Invalid server response"));
      }
    };
    xhr.onerror = () => reject(new Error("Network unavailable or the server did not respond"));
    xhr.send(data);
  });
}

function Field({
  label,
  name,
  required,
  placeholder,
  type = "text",
  disabled,
}: {
  label: string;
  name: string;
  required?: boolean;
  placeholder?: string;
  type?: string;
  disabled?: boolean;
}) {
  const t = useT();
  return (
    <label className="block space-y-2">
      <span className="text-[13px] font-semibold text-ink">{t(label)}</span>
      <input
        name={name}
        type={type}
        required={required}
        placeholder={placeholder}
        disabled={disabled}
        className="field-input"
      />
    </label>
  );
}
