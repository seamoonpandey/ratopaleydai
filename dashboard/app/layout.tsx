import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import { Shield } from "lucide-react";
import { AuthProvider } from "@/hooks/use-auth";
import { UserMenu } from "@/components/user-menu";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "RedSentinel — AI XSS Scanner",
  description: "AI-powered XSS vulnerability scanner dashboard",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} min-h-screen bg-[#09090b] font-sans text-zinc-100 antialiased`}
      >
        <AuthProvider>
          {/* ── navbar ─────────────────────────────────────── */}
          <header className="sticky top-0 z-50 border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-md">
            <nav className="mx-auto flex h-14 max-w-7xl items-center gap-6 px-6">
              <Link href="/" className="flex items-center gap-2 text-emerald-400">
                <Shield size={20} />
                <span className="text-sm font-bold tracking-wide">
                  RedSentinel
                </span>
              </Link>
              <div className="flex flex-1 gap-4 text-sm text-zinc-400">
                <Link href="/" className="transition-colors hover:text-zinc-100">
                  Dashboard
                </Link>
              </div>
              <UserMenu />
            </nav>
          </header>

          {/* ── content ────────────────────────────────────── */}
          <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
        </AuthProvider>
      </body>
    </html>
  );
}
