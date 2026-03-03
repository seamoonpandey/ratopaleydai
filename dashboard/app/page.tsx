"use client";

import { useEffect, useState, useCallback } from "react";
import { listScans, getHealth, deleteAllScans } from "@/lib/api";
import type { Scan, HealthReport, ProgressEvent, CompleteEvent, ErrorEvent } from "@/lib/types";
import { ScanStatus } from "@/lib/types";
import { NewScanForm } from "@/components/new-scan-form";
import { ScanTable } from "@/components/scan-table";
import { Card, StatCard } from "@/components/ui";
import { useScanSocket } from "@/hooks/use-scan-socket";
import { Activity, Shield, AlertTriangle, Wifi, Trash2 } from "lucide-react";

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [scanList, healthReport] = await Promise.all([
        listScans(),
        getHealth().catch(() => null),
      ]);
      setScans(scanList);
      setHealth(healthReport);
    } catch {
      /* api may be unreachable on first load */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  /* update scan progress in real-time via websocket */
  const handleProgress = useCallback((e: ProgressEvent) => {
    setScans((prev) =>
      prev.map((s) =>
        s.id === e.scanId
          ? { ...s, progress: e.progress, phase: e.phase }
          : s,
      ),
    );
  }, []);

  const handleComplete = useCallback((e: CompleteEvent) => {
    setScans((prev) =>
      prev.map((s) =>
        s.id === e.scanId
          ? { ...s, status: ScanStatus.DONE, progress: 100 }
          : s,
      ),
    );
  }, []);

  const handleError = useCallback((e: ErrorEvent) => {
    setScans((prev) =>
      prev.map((s) =>
        s.id === e.scanId
          ? { ...s, status: ScanStatus.FAILED, error: e.message }
          : s,
      ),
    );
  }, []);

  const { connected } = useScanSocket({
    onProgress: handleProgress,
    onComplete: handleComplete,
    onError: handleError,
  });

  const handleScanCreated = (scan: Scan) => {
    setScans((prev) => [scan, ...prev]);
  };

  const handleClearAll = async () => {
    if (!confirm("Delete ALL scans, results, and reports? This cannot be undone.")) return;
    try {
      await deleteAllScans();
      setScans([]);
    } catch {
      /* api may be unreachable */
    }
  };

  const activeScans = scans.filter(
    (s) => s.status !== ScanStatus.DONE && s.status !== ScanStatus.FAILED && s.status !== ScanStatus.CANCELLED,
  ).length;
  const totalVulns = scans.reduce(
    (sum, s) => sum + (s.vulns?.length ?? 0),
    0,
  );
  const completedScans = scans.filter((s) => s.status === ScanStatus.DONE).length;

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-zinc-500">
        Loading...
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* ── header ──────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Dashboard</h1>
          <p className="text-sm text-zinc-400">
            AI-powered XSS vulnerability scanner
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Wifi
            size={14}
            className={connected ? "text-emerald-400" : "text-red-400"}
          />
          <span className={connected ? "text-emerald-400" : "text-red-400"}>
            {connected ? "Live" : "Disconnected"}
          </span>
          {health && (
            <span
              className={`ml-2 rounded-full px-2 py-0.5 text-xs ${
                health.status === "healthy"
                  ? "bg-emerald-600/20 text-emerald-400"
                  : health.status === "degraded"
                    ? "bg-amber-600/20 text-amber-400"
                    : "bg-red-600/20 text-red-400"
              }`}
            >
              {health.status}
            </span>
          )}
        </div>
      </div>

      {/* ── stats ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          label="Active Scans"
          value={activeScans}
          icon={<Activity size={20} />}
        />
        <StatCard
          label="Completed"
          value={completedScans}
          icon={<Shield size={20} />}
        />
        <StatCard
          label="Total Vulns"
          value={totalVulns}
          icon={<AlertTriangle size={20} />}
        />
      </div>

      {/* ── new scan ────────────────────────────────────── */}
      <Card>
        <h2 className="mb-4 text-lg font-semibold text-zinc-100">New Scan</h2>
        <NewScanForm onCreated={handleScanCreated} />
      </Card>

      {/* ── scan list ───────────────────────────────────── */}
      <Card>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-zinc-100">
            Recent Scans
          </h2>
          {scans.length > 0 && (
            <button
              onClick={handleClearAll}
              className="inline-flex items-center gap-1.5 rounded-md bg-red-600/20 px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-600/30"
            >
              <Trash2 size={13} />
              Clear All
            </button>
          )}
        </div>
        <ScanTable scans={scans} onDelete={(id) => setScans((prev) => prev.filter((s) => s.id !== id))} />
      </Card>
    </div>
  );
}
