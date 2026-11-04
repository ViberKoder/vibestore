import { NextResponse } from "next/server";
import { connection } from "next/server";
import { storageStatus } from "@/lib/store";

/**
 * Liveness + storage probe for Railway / Docker.
 * `storage.persistent: false` means the catalog is NOT on a volume and will be
 * lost on redeploy.
 */
export async function GET() {
  await connection();
  const storage = await storageStatus();
  return NextResponse.json({ ok: true, storage });
}
