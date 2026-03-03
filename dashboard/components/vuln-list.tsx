"use client";

import type { Vuln } from "@/lib/types";
import { VulnType } from "@/lib/types";
import { SeverityBadge } from "@/components/ui";

const isDomXss = (v: Vuln) =>
  v.type === VulnType.DOM_XSS || v.type === VulnType.OPEN_REDIRECT;

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
      {vulns.map((v, i) => {
        const domXss = isDomXss(v);
        const ev = v.evidence;
        return (
          <div
            key={v.id ?? i}
            className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4"
          >
            {/* ── header row ── */}
            <div className="mb-2 flex flex-wrap items-center gap-3">
              <SeverityBadge severity={v.severity} />
              <span className="text-sm font-medium text-zinc-200">
                {v.type.replace(/_/g, " ")}
              </span>
              <span className="ml-auto text-xs text-zinc-500">
                {domXss ? "source" : "param"}:{" "}
                <code className="text-zinc-300">{v.param}</code>
              </span>
            </div>

            {/* ── page URL ── */}
            <div className="mb-2 truncate text-xs text-zinc-500">
              <span className="mr-1 text-zinc-600">page:</span>
              <a
                href={v.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sky-400 hover:underline"
              >
                {v.url}
              </a>
            </div>

            {/* ── payload / finding ── */}
            <div className="mb-2 overflow-x-auto rounded bg-zinc-950 p-2">
              <code className="whitespace-pre text-xs text-amber-400">
                {v.payload}
              </code>
            </div>

            {/* ── DOM XSS details ── */}
            {domXss && (ev.sink || ev.snippet) && (
              <div className="mb-2 space-y-1 rounded bg-zinc-950/60 p-2 text-xs">
                {ev.sink && (
                  <div>
                    <span className="text-zinc-500">sink: </span>
                    <code className="text-rose-400">{ev.sink}</code>
                    {ev.line && (
                      <span className="ml-2 text-zinc-600">line {ev.line}</span>
                    )}
                  </div>
                )}
                {ev.source && (
                  <div>
                    <span className="text-zinc-500">source: </span>
                    <code className="text-orange-400">{ev.source}</code>
                  </div>
                )}
                {ev.snippet && (
                  <div className="mt-1 overflow-x-auto">
                    <span className="text-zinc-500">snippet: </span>
                    <code className="text-zinc-400">{ev.snippet}</code>
                  </div>
                )}
                {ev.scriptUrl && ev.scriptUrl !== v.url && (
                  <div className="truncate">
                    <span className="text-zinc-500">script: </span>
                    <span className="text-zinc-400">{ev.scriptUrl}</span>
                  </div>
                )}
              </div>
            )}

            {/* ── flags row ── */}
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
              {!domXss && (
                <span>
                  Position:{" "}
                  <span className="text-zinc-300">{ev.reflectionPosition}</span>
                </span>
              )}
              <span>
                HTTP{" "}
                <span className="text-zinc-300">{ev.responseCode}</span>
              </span>
              {ev.browserAlertTriggered && (
                <span className="text-red-400">⚡ alert triggered</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
