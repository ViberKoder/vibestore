/** Content-Disposition for downloads: ASCII fallback plus RFC 5987 UTF-8 name. */
export function contentDisposition(name: string): string {
  const cleaned = name.replace(/[\u0000-\u001f\u007f"\\/]/g, "_").slice(0, 200) || "download.bin";
  const ascii = cleaned.replace(/[^\x20-\x7e]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(cleaned)}`;
}
