/* ── scan types ──────────────────────────────────────────────── */

export enum ScanStatus {
  PENDING = "PENDING",
  CRAWLING = "CRAWLING",
  ANALYZING = "ANALYZING",
  GENERATING = "GENERATING",
  FUZZING = "FUZZING",
  REPORTING = "REPORTING",
  DONE = "DONE",
  FAILED = "FAILED",
  CANCELLED = "CANCELLED",
}

export enum ScanPhase {
  CRAWL = "CRAWL",
  CONTEXT = "CONTEXT",
  PAYLOAD_GEN = "PAYLOAD_GEN",
  FUZZ = "FUZZ",
  REPORT = "REPORT",
}

export interface ScanOptions {
  depth?: number;
  maxParams?: number;
  verifyExecution?: boolean;
  wafBypass?: boolean;
  maxPayloadsPerParam?: number;
  timeout?: number;
  reportFormat?: ("html" | "json" | "pdf")[];
  singlePage?: boolean;
}

export interface Scan {
  id: string;
  url: string;
  status: ScanStatus;
  phase?: ScanPhase;
  progress: number;
  options: ScanOptions;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  error?: string;
  vulns?: Vuln[];
}

/* ── vuln types ─────────────────────────────────────────────── */

export enum VulnType {
  REFLECTED_XSS = "reflected_xss",
  STORED_XSS = "stored_xss",
  DOM_XSS = "dom_xss",
  OPEN_REDIRECT = "open_redirect",
}

export enum VulnSeverity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
  INFO = "INFO",
}

export interface VulnEvidence {
  responseCode: number;
  reflectionPosition: string;
  browserAlertTriggered: boolean;
  screenshot?: string;
  /* DOM-XSS specific fields */
  sink?: string;
  source?: string;
  line?: number;
  snippet?: string;
  scriptUrl?: string;
}

export interface Vuln {
  id?: string;
  scanId: string;
  param: string;
  payload: string;
  type: VulnType;
  severity: VulnSeverity;
  url: string;
  reflected: boolean;
  executed: boolean;
  evidence: VulnEvidence;
  discoveredAt: string;
}

/* ── websocket event types ──────────────────────────────────── */

export interface ProgressEvent {
  scanId: string;
  phase: ScanPhase;
  progress: number;
  message: string;
}

export interface FindingEvent {
  scanId: string;
  vuln: Partial<Vuln>;
}

export interface CompleteEvent {
  scanId: string;
  summary: {
    totalParams: number;
    paramsTested: number;
    vulnsFound: number;
    durationMs: number;
  };
  reportUrl?: string;
}

export interface ErrorEvent {
  scanId: string;
  message: string;
}

/* ── health types ───────────────────────────────────────────── */

export interface ServiceHealth {
  name: string;
  status: "up" | "down";
  latencyMs: number;
  detail?: string;
}

export interface HealthReport {
  status: "healthy" | "degraded" | "unhealthy";
  uptime: number;
  timestamp: string;
  services: ServiceHealth[];
}

/* ── report types ───────────────────────────────────────────── */

export interface ReportFormats {
  scanId: string;
  formats: string[];
  /** Formats that exist on disk but have empty/corrupt content. */
  broken: string[];
  links: Record<string, string>;
}
