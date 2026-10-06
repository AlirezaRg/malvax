"use client";

import { useRouter } from "next/navigation";

export function LogoutButton() {
  const router = useRouter();

  async function signOut() {
    await fetch("/api/session", { method: "DELETE" });
    router.replace("/login");
    router.refresh();
  }

  return (
    <button onClick={signOut} className="text-zinc-400 hover:text-zinc-100">
      Sign out
    </button>
  );
}
