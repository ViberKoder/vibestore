import { NextResponse } from "next/server";
import { connection } from "next/server";

/** Liveness probe for Railway / Docker. Cheap: no disk or scanner calls. */
export async function GET() {
  await connection();
  return NextResponse.json({ ok: true });
}
