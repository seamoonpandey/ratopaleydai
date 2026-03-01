"use client";

import type { Vuln } from "@/lib/types";
import { SeverityBadge } from "@/components/ui";

export function VulnList({ vulns }: { vulns: Vuln[] }) {
  if (vulns.length === 0) {
    return (
      <div className="py-8 text-center text-zinc-500">
        No vulnerabilities found.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {vulns.map((v, i) => (
        <div
          key={v.id ?? i}
          className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4"
        >
          <div className="mb-2 flex items-center gap-3">
            <SeverityBadge severity={v.severity} />
            <span className="text-sm font-medium text-zinc-200">
              {v.type.replace(/_/g, " ")}
            </span>
            <span className="ml-auto text-xs text-zinc-500">
              param: <code className="text-zinc-300">{v.param}</code>
            </span>
          </div>

          <div className="mb-2 overflow-x-auto rounded bg-zinc-950 p-2">
            <code className="whitespace-pre text-xs text-amber-400">
              {v.payload}
            </code>
          </div>

          <div className="flex flex-wrap gap-4 text-xs text-zinc-400">
            <span>
              Reflected:{" "}
              <span className={v.reflected ? "text-emerald-400" : "text-zinc-500"}>
                {v.reflected ? "yes" : "no"}
              </span>
            </span>
            <span>
              Executed:{" "}
              <span className={v.executed ? "text-red-400" : "text-zinc-500"}>
                {v.executed ? "yes" : "no"}
              </span>
            </span>
            <span>
              Position:{" "}
              <span className="text-zinc-300">
                {v.evidence.reflectionPosition}
              </span>
            </span>
            <span>
              HTTP{" "}
              <span className="text-zinc-300">
                {v.evidence.responseCode}
              </span>
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
