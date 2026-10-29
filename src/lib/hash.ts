import { createHash } from "crypto";

export function sha256Buffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

export function shortHash(hex: string, len = 12): string {
  return hex.slice(0, len);
}
