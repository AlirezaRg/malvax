// Session token lives in an httpOnly cookie, so page scripts cannot read it.
// Only server code (route handlers, server components, middleware) touches it.

import { cookies } from "next/headers";

export const SESSION_COOKIE = "malvax_session";
export const SESSION_MAX_AGE_S = 60 * 60; // matches the API token lifetime (60 minutes)

export function readToken(): string | null {
  return cookies().get(SESSION_COOKIE)?.value ?? null;
}

export function cookieSecure(): boolean {
  // Off by default so the lab works over plain http://localhost. Turn on behind TLS.
  return process.env.MALVAX_COOKIE_SECURE === "1";
}
