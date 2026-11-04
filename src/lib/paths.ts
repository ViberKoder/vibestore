import path from "path";

/**
 * Where runtime data lives (store.json, uploads, media).
 * Local dev: ./data. On Railway/Docker: set VIBE_DATA_DIR to the mounted volume (e.g. /data).
 */
export const DATA_DIR = process.env.VIBE_DATA_DIR?.trim()
  ? path.resolve(process.env.VIBE_DATA_DIR.trim())
  : path.join(process.cwd(), "data");
export const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
export const MEDIA_DIR = path.join(DATA_DIR, "media");
export const DB_PATH = path.join(DATA_DIR, "store.json");
