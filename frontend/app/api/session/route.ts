// Server-side login and logout. The browser never sees the API token: it is stored only in an
// httpOnly cookie that this route sets.

import { NextResponse } from "next/server";
import { API_BASE } from "@/lib/api";
import { SESSION_COOKIE, SESSION_MAX_AGE_S, cookieSecure } from "@/lib/session";

export async function POST(request: Request) {
  const body = (await request.json().catch(() => null)) as {
    username?: unknown;
    password?: unknown;
  } | null;
  if (!body || typeof body.username !== "string" || typeof body.password !== "string") {
    return NextResponse.json({ detail: "username and password are required" }, { status: 422 });
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: body.username, password: body.password }),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ detail: "API is not reachable" }, { status: 502 });
  }

  if (!upstream.ok) {
    // Same message for every failure, so the response does not reveal which part was wrong.
    return NextResponse.json({ detail: "invalid username or password" }, { status: 401 });
  }

  const data = (await upstream.json()) as { access_token: string; role: string };
  const response = NextResponse.json({ role: data.role });
  response.cookies.set(SESSION_COOKIE, data.access_token, {
    httpOnly: true,
    sameSite: "strict",
    secure: cookieSecure(),
    path: "/",
    maxAge: SESSION_MAX_AGE_S,
  });
  return response;
}

export async function DELETE() {
  const response = NextResponse.json({ signedOut: true });
  response.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "strict",
    secure: cookieSecure(),
    path: "/",
    maxAge: 0,
  });
  return response;
}
