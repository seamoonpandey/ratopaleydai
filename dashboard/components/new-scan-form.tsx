"use client";

import { useState } from "react";
import { createScan } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { Crosshair } from "lucide-react";

interface NewScanFormProps {
  onCreated: (scan: Scan) => void;
}

export function NewScanForm({ onCreated }: NewScanFormProps) {
  const [url, setUrl] = useState("");
  const [depth, setDepth] = useState(3);
  const [maxPayloads, setMaxPayloads] = useState(50);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const scan = await createScan(url, {
        depth,
        maxPayloadsPerParam: maxPayloads,
        reportFormat: ["html", "json", "pdf"],
      });
      setUrl("");
      onCreated(scan);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="url" className="mb-1 block text-sm text-zinc-400">
          Target URL
        </label>
        <input
          id="url"
          type="url"
          required
          placeholder="https://target.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label htmlFor="depth" className="mb-1 block text-sm text-zinc-400">
            Crawl Depth
          </label>
          <input
            id="depth"
            type="number"
            min={1}
            max={10}
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm text-zinc-100 outline-none focus:border-emerald-500"
          />
        </div>
        <div>
          <label
            htmlFor="maxPayloads"
            className="mb-1 block text-sm text-zinc-400"
          >
            Max Payloads / Param
          </label>
          <input
            id="maxPayloads"
            type="number"
            min={5}
            max={200}
            value={maxPayloads}
            onChange={(e) => setMaxPayloads(Number(e.target.value))}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm text-zinc-100 outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      {error && (
        <p className="text-sm text-red-400">{error}</p>
      )}

      <button
        type="submit"
        disabled={loading}
        className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50"
      >
        <Crosshair size={16} />
        {loading ? "Starting Scan..." : "Start Scan"}
      </button>
    </form>
  );
}
