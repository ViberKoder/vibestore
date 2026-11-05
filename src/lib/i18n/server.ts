import { cookies } from "next/headers";
import { LOCALE_COOKIE, makeT, parseLocale, type Locale } from "./core";

/** Locale for the current request (cookie `vibe_lang`, default English). */
export async function getLocale(): Promise<Locale> {
  return parseLocale((await cookies()).get(LOCALE_COOKIE)?.value);
}

export async function getT() {
  return makeT(await getLocale());
}
