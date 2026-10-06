import Link from "next/link";
import type { ReactNode } from "react";
import { ApiError } from "@/lib/api";

export function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto border border-zinc-800">
      <table className="w-full text-left">
        <thead className="bg-zinc-900 text-zinc-400">
          <tr>
            {headers.map((h) => (
              <th key={h} className="px-3 py-2 font-normal">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">{children}</tbody>
      </table>
    </div>
  );
}

export function Empty({ text }: { text: string }) {
  return <p className="text-zinc-500 py-6">{text}</p>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.status === 401) {
    return (
      <div className="border border-amber-800 bg-amber-950/40 p-3 text-amber-300">
        Your session is missing or has expired.{" "}
        <Link className="underline" href="/login">
          Sign in again
        </Link>
        .
      </div>
    );
  }
  const message = error instanceof Error ? error.message : "unknown error";
  return (
    <div className="border border-red-800 bg-red-950/40 p-3 text-red-300">
      Could not load data from the MalvaX API: {message}
    </div>
  );
}
