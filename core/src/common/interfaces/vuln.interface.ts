export enum VulnType {
  REFLECTED_XSS = 'reflected_xss',
  STORED_XSS = 'stored_xss',
  DOM_XSS = 'dom_xss',
}

export enum VulnSeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

export interface VulnEvidence {
  responseCode: number;
  reflectionPosition: string;
  browserAlertTriggered: boolean;
  exactMatch?: boolean;
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
  discoveredAt: Date;
}
