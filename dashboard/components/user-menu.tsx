"use client";

import { User, LogOut, Key } from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { getApiKey } from "@/lib/api";

export function UserMenu() {
  const { user, logout } = useAuth();
  const [showMenu, setShowMenu] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKey, setApiKey] = useState<string | null>(null);

  if (!user) return null;

  const handleGetApiKey = async () => {
    try {
      const { apiKey: key } = await getApiKey();
      setApiKey(key);
      setShowApiKey(true);
    } catch (error) {
      console.error("Failed to get API key:", error);
    }
  };

  return (
    <div className="relative">
      <button
        onClick={() => setShowMenu(!showMenu)}
        className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 transition-colors hover:border-emerald-500/50"
      >
        {user.avatar ? (
          <img src={user.avatar} alt={user.name || user.email} className="h-6 w-6 rounded-full" />
        ) : (
          <User size={16} className="text-zinc-400" />
        )}
        <span className="text-sm text-zinc-300">{user.name || user.email}</span>
      </button>

      {showMenu && (
        <div className="absolute right-0 mt-2 w-64 rounded-lg border border-zinc-800 bg-zinc-900 shadow-xl">
          <div className="border-b border-zinc-800 p-3">
            <p className="text-sm font-medium text-zinc-100">{user.name}</p>
            <p className="text-xs text-zinc-500">{user.email}</p>
            <p className="mt-1 text-xs text-zinc-600">via {user.provider}</p>
          </div>
          <div className="p-2">
            <button
              onClick={handleGetApiKey}
              className="flex w-full items-center gap-2 rounded px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
            >
              <Key size={16} />
              Get API Key
            </button>
            <button
              onClick={logout}
              className="flex w-full items-center gap-2 rounded px-3 py-2 text-sm text-red-400 hover:bg-zinc-800"
            >
              <LogOut size={16} />
              Sign Out
            </button>
          </div>
        </div>
      )}

      {showApiKey && apiKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6">
            <h3 className="mb-4 text-lg font-semibold text-zinc-100">Your API Key</h3>
            <div className="mb-4 rounded border border-zinc-700 bg-zinc-950 p-3">
              <code className="break-all text-sm text-emerald-400">{apiKey}</code>
            </div>
            <p className="mb-4 text-sm text-zinc-400">
              Use this key for programmatic access. Keep it secure!
            </p>
            <button
              onClick={() => setShowApiKey(false)}
              className="w-full rounded bg-emerald-500 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-600"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
