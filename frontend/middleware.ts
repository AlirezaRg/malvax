// Sends visitors without a session cookie to /login. This is a convenience gate; the API
// still enforces roles on every request, so a forged or expired cookie gets 401 from the API.

import { NextResponse, type NextRequest } from "next/server";

const SESSION_COOKIE = "malvax_session";
const PUBLIC_PATHS = ["/login"];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (PUBLIC_PATHS.includes(pathname)) {
    return NextResponse.next();
  }
  if (!request.cookies.get(SESSION_COOKIE)) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  // Skip Next internals and the session route itself.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/session).*)"],
};
