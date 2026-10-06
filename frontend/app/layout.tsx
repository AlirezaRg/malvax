import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { LogoutButton } from "@/components/LogoutButton";

export const metadata: Metadata = {
  title: "MalvaX",
  description: "Linux malware analysis and behavioral sandbox (laboratory use only)",
};

const nav = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/samples", label: "Samples" },
  { href: "/analyses", label: "Analyses" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-mono text-sm">
        <header className="border-b border-zinc-800 px-6 py-3 flex items-center gap-6">
          <span className="font-semibold tracking-wide text-zinc-100">MalvaX</span>
          <nav className="flex gap-4 text-zinc-400">
            {nav.map((item) => (
              <Link key={item.href} href={item.href} className="hover:text-zinc-100">
                {item.label}
              </Link>
            ))}
          </nav>
          <span className="ml-auto text-xs text-amber-400">Laboratory use only</span>
          <LogoutButton />
        </header>
        <main className="px-6 py-6 max-w-6xl mx-auto">{children}</main>
      </body>
    </html>
  );
}
