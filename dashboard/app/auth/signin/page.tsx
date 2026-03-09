"use client";

import { Shield, Github } from "lucide-react";
import Link from "next/link";

export default function SignInPage() {
  const coreApiUrl = process.env.NEXT_PUBLIC_CORE_API_URL || "http://localhost:3000";

  const handleGoogleSignIn = () => {
    window.location.href = `${coreApiUrl}/auth/google`;
  };

  const handleGitHubSignIn = () => {
    window.location.href = `${coreApiUrl}/auth/github`;
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-zinc-950 via-zinc-900 to-emerald-950/20">
      <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-950/80 p-8 shadow-2xl backdrop-blur-sm">
        {/* Logo */}
        <div className="mb-8 flex items-center justify-center gap-3">
          <Shield className="h-10 w-10 text-emerald-400" />
          <h1 className="text-3xl font-bold text-zinc-100">RedSentinel</h1>
        </div>

        {/* Title */}
        <div className="mb-8 text-center">
          <h2 className="text-2xl font-semibold text-zinc-100">Welcome back</h2>
          <p className="mt-2 text-sm text-zinc-400">
            Sign in to access the XSS scanner dashboard
          </p>
        </div>

        {/* OAuth Buttons */}
        <div className="space-y-3">
          <button
            onClick={handleGoogleSignIn}
            className="flex w-full items-center justify-center gap-3 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 font-medium text-zinc-100 transition-all hover:border-emerald-500/50 hover:bg-zinc-800"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24">
              <path
                fill="currentColor"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="currentColor"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="currentColor"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="currentColor"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            Continue with Google
          </button>

          <button
            onClick={handleGitHubSignIn}
            className="flex w-full items-center justify-center gap-3 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 font-medium text-zinc-100 transition-all hover:border-emerald-500/50 hover:bg-zinc-800"
          >
            <Github className="h-5 w-5" />
            Continue with GitHub
          </button>
        </div>

        {/* Footer */}
        <div className="mt-6 text-center text-sm text-zinc-500">
          By signing in, you agree to our{" "}
          <Link href="/terms" className="text-emerald-400 hover:underline">
            Terms of Service
          </Link>
        </div>
      </div>
    </div>
  );
}
