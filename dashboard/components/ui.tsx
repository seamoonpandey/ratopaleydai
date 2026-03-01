"use client";

import { ScanStatus, VulnSeverity } from "@/lib/types";

/* ── status badge ───────────────────────────────────────────── */

const statusColors: Record<string, string> = {
  [ScanStatus.PENDING]: "bg-zinc-700 text-zinc-200",
  [ScanStatus.CRAWLING]: "bg-blue-600/20 text-blue-400",
  [ScanStatus.ANALYZING]: "bg-violet-600/20 text-violet-400",
  [ScanStatus.GENERATING]: "bg-amber-600/20 text-amber-400",
  [ScanStatus.FUZZING]: "bg-orange-600/20 text-orange-400",
  [ScanStatus.REPORTING]: "bg-cyan-600/20 text-cyan-400",
  [ScanStatus.DONE]: "bg-emerald-600/20 text-emerald-400",
  [ScanStatus.FAILED]: "bg-red-600/20 text-red-400",
  [ScanStatus.CANCELLED]: "bg-zinc-600/20 text-zinc-400",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${statusColors[status] ?? "bg-zinc-700 text-zinc-300"}`}
    >
      {status}
    </span>
  );
}

/* ── severity badge ─────────────────────────────────────────── */

const severityColors: Record<string, string> = {
  [VulnSeverity.CRITICAL]: "bg-red-600 text-white",
  [VulnSeverity.HIGH]: "bg-orange-600 text-white",
  [VulnSeverity.MEDIUM]: "bg-amber-500 text-black",
  [VulnSeverity.LOW]: "bg-yellow-400 text-black",
  [VulnSeverity.INFO]: "bg-sky-500/20 text-sky-400",
};

export function SeverityBadge({ severity }: { severity: VulnSeverity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase ${severityColors[severity] ?? "bg-zinc-700 text-zinc-300"}`}
    >
      {severity}
    </span>
  );
}

/* ── progress bar ───────────────────────────────────────────── */

export function ProgressBar({
  value,
  label,
}: {
  value: number;
  label?: string;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className="w-full">
      {label && (
        <div className="mb-1 flex justify-between text-xs text-zinc-400">
          <span>{label}</span>
          <span>{clamped}%</span>
        </div>
      )}
      <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-800">
        <div
          className="h-full rounded-full bg-emerald-500 transition-all duration-500"
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
}

/* ── card ────────────────────────────────────────────────────── */

export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-xl border border-zinc-800 bg-zinc-900/50 p-5 ${className}`}
    >
      {children}
    </div>
  );
}

/* ── stat card ──────────────────────────────────────────────── */

export function StatCard({
  label,
  value,
  icon,
}: {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
}) {
  return (
    <Card className="flex items-center gap-4">
      {icon && (
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-800 text-zinc-400">
          {icon}
        </div>
      )}
      <div>
        <p className="text-sm text-zinc-400">{label}</p>
        <p className="text-2xl font-bold text-zinc-100">{value}</p>
      </div>
    </Card>
  );
}
