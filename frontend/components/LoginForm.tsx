"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

export function LoginForm() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { detail?: string };
        setError(body.detail ?? "sign-in failed");
        return;
      }
      setPassword("");
      router.replace("/dashboard");
      router.refresh();
    } catch {
      setError("could not reach the server");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="max-w-sm space-y-3" onSubmit={submit}>
      <input
        className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2"
        placeholder="username"
        autoComplete="username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required
      />
      <input
        className="w-full bg-zinc-900 border border-zinc-800 px-3 py-2"
        type="password"
        placeholder="password"
        autoComplete="current-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
      />
      {error && <p className="text-red-400">{error}</p>}
      <button
        className="border border-zinc-700 px-3 py-2 text-zinc-200 hover:bg-zinc-900 disabled:opacity-50"
        disabled={busy}
      >
        {busy ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
