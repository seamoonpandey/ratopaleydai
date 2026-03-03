"use client";

import Link from "next/link";
import type { Scan } from "@/lib/types";
import { ScanStatus } from "@/lib/types";
import { StatusBadge, ProgressBar } from "@/components/ui";
import { ExternalLink, Trash2 } from "lucide-react";
import { deleteScan } from "@/lib/api";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ScanTable({ scans, onDelete }: { scans: Scan[]; onDelete?: (id: string) => void }) {
  if (scans.length === 0) {
    return (
      <div className="py-16 text-center text-zinc-500">
        No scans yet. Start one above.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-zinc-800 text-zinc-400">
            <th className="px-4 py-3 font-medium">Target</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Progress</th>
            <th className="px-4 py-3 font-medium">Vulns</th>
            <th className="px-4 py-3 font-medium">Started</th>
            <th className="px-4 py-3 font-medium" />
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-800/30"
            >
              <td className="px-4 py-3">
                <span className="font-mono text-xs text-zinc-300">
                  {scan.url}
                </span>
              </td>
              <td className="px-4 py-3">
                <StatusBadge status={scan.status} />
              </td>
              <td className="w-40 px-4 py-3">
                {scan.status !== ScanStatus.DONE &&
                scan.status !== ScanStatus.FAILED &&
                scan.status !== ScanStatus.CANCELLED ? (
                  <ProgressBar value={scan.progress} />
                ) : (
                  <span className="text-xs text-zinc-500">—</span>
                )}
              </td>
              <td className="px-4 py-3">
                <span
                  className={`text-sm font-semibold ${(scan.vulns?.length ?? 0) > 0 ? "text-red-400" : "text-zinc-500"}`}
                >
                  {scan.vulns?.length ?? 0}
                </span>
              </td>
              <td className="px-4 py-3 text-xs text-zinc-500">
                {formatDate(scan.createdAt)}
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <Link
                    href={`/scan/${scan.id}`}
                    className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
                  >
                    View <ExternalLink size={12} />
                  </Link>
                  <button
                    onClick={async () => {
                      if (!confirm("Delete this scan and its results?")) return;
                      try {
                        await deleteScan(scan.id);
                        onDelete?.(scan.id);
                      } catch { /* ignore */ }
                    }}
                    className="inline-flex items-center gap-1 text-xs text-red-400/60 hover:text-red-400 transition-colors"
                    title="Delete scan"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
