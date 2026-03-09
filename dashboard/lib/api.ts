import type { Scan, ScanOptions, HealthReport, ReportFormats } from "./types";

const BASE = "/api";

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };

  // Use JWT token for authentication
  const token =
    typeof window !== "undefined"
      ? localStorage.getItem("rs-auth-token") ?? ""
      : "";
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Fallback to API key for backwards compatibility
  if (!token) {
    const apiKey =
      typeof window !== "undefined"
        ? localStorage.getItem("rs-api-key") ?? ""
        : "";
    if (apiKey) headers["x-api-key"] = apiKey;
  }

  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

/* ── scans ──────────────────────────────────────────────────── */

export async function createScan(
  url: string,
  options?: Partial<ScanOptions>,
): Promise<Scan> {
  return request<Scan>("/scan", {
    method: "POST",
    body: JSON.stringify({ url, options }),
  });
}

export async function getScan(id: string): Promise<Scan> {
  return request<Scan>(`/scan/${id}`);
}

export async function listScans(
  page = 1,
  limit = 20,
): Promise<Scan[]> {
  return request<Scan[]>(`/scans?page=${page}&limit=${limit}`);
}

export async function cancelScan(id: string): Promise<void> {
  await request<void>(`/scan/${id}`, { method: "DELETE" });
}

export async function deleteScan(id: string): Promise<void> {
  await request<void>(`/scans/${id}`, { method: "DELETE" });
}

export async function deleteAllScans(): Promise<{ deleted: number }> {
  return request<{ deleted: number }>("/scans", { method: "DELETE" });
}

/* ── health ─────────────────────────────────────────────────── */

export async function getHealth(): Promise<HealthReport> {
  return request<HealthReport>("/health");
}

/* ── reports ────────────────────────────────────────────────── */

export async function getReportFormats(scanId: string): Promise<ReportFormats> {
  return request<ReportFormats>(`/reports/${scanId}`);
}

export function getReportDownloadUrl(
  scanId: string,
  format: string,
): string {
  return `${BASE}/reports/${scanId}/download?format=${format}`;
}

export async function regenerateReport(
  scanId: string,
  formats: string[] = ['html', 'json', 'pdf'],
): Promise<ReportFormats> {
  const fmtParam = formats.join(',');
  // Trigger backend regeneration then re-fetch the updated formats list
  await request<unknown>(`/reports/${scanId}/regenerate?formats=${fmtParam}`);
  return request<ReportFormats>(`/reports/${scanId}`);
}

/* ── auth ───────────────────────────────────────────────────── */

export interface User {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  provider: string;
}

export async function getCurrentUser(): Promise<User> {
  return request<User>("/auth/me");
}

export async function getApiKey(): Promise<{ apiKey: string }> {
  return request<{ apiKey: string }>("/auth/api-key");
}
