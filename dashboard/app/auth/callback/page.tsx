"use client";

import { useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";

export default function AuthCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  
  useEffect(() => {
    const token = searchParams.get("token");
    if (token) {
      // Store JWT token from backend
      localStorage.setItem("rs-auth-token", token);
      // Redirect to dashboard
      router.push("/");
    } else {
      // No token, redirect to login
      router.push("/auth/signin");
    }
  }, [searchParams, router]);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <div className="mb-4 inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-emerald-400 border-r-transparent"></div>
        <p className="text-zinc-400">Completing sign in...</p>
      </div>
    </div>
  );
}
