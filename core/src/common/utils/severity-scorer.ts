import { VulnSeverity } from '../interfaces/vuln.interface';

/**
 * Rule-based severity scorer for XSS findings.
 *
 * Scoring matrix:
 *   Execution:    executed → 3, reflected → 2, dom-only → 1
 *   Shareability: URL param → 3, postMessage/e.data → 2, URLSearchParams/hash → 1
 *   Sink danger:  eval/document.write/location.assign/script → 3, innerHTML/html_body → 2, attribute → 1
 *   Payload:      document.cookie → 3, localStorage → 2, alert triggered → 1, % (WAF bypass) → 1
 *
 * Total → Severity: 8+ CRITICAL, 6-7 HIGH, 4-5 MEDIUM, 0-3 LOW
 *
 * Override rules applied after scoring:
 *   1. HASH_SOURCE_LOW_CAP:          source=location.hash → max LOW
 *   2. EVAL_SINK_MINIMUM_HIGH:       sink=eval/script     → min HIGH
 *   3. CONFIRMED_SENSITIVE_EXEC:     executed + document.cookie → CRITICAL
 *   4. WAF_BYPASS_MEDIUM_MINIMUM:    reflected + % + exactMatch → min MEDIUM
 *   5. POSTMESSAGE_MEDIUM_MINIMUM:   source=e.data/postMessage → min MEDIUM
 */

export interface ScoringInput {
  reflected: boolean;
  executed: boolean;
  payload: string;
  source: string;
  sink: string;
  exactMatch: boolean;
  browserAlertTriggered: boolean;
}

export interface ScoringResult {
  severity: VulnSeverity;
  score: number;
  breakdown: {
    execution: number;
    shareability: number;
    sinkDanger: number;
    payload: number;
  };
  appliedOverrides: string[];
}

// ── Individual scorers ──────────────────────────────────────

export function getExecutionScore(input: ScoringInput): number {
  if (input.executed) return 3;
  if (input.reflected) return 2;
  return 1; // DOM-only
}

export function getShareabilityScore(input: ScoringInput): number {
  const s = (input.source ?? '').toLowerCase();

  // URL param (query string param reflected) = highest shareability
  if (s === '' || s === 'url' || s === 'url param' || s === 'urlsearchparams') {
    return 3;
  }
  if (s === 'postmessage' || s === 'e.data') return 2;
  if (s === 'location.hash' || s === 'hash') return 1;
  // Default: treat unknown sources as URL param (most common case)
  return 3;
}

export function getSinkDangerScore(input: ScoringInput): number {
  const sk = (input.sink ?? '').toLowerCase();
  if (
    sk === 'eval' ||
    sk === 'script' ||
    sk === 'document.write' ||
    sk === 'location.assign'
  ) {
    return 3;
  }
  if (sk === 'innerhtml' || sk === 'html_body') return 2;
  if (sk === 'attribute' || sk === 'href') return 1;
  // Default: attribute-level
  return 1;
}

export function getPayloadScore(input: ScoringInput): number {
  const p = input.payload ?? '';
  let score = 0;
  if (p.includes('document.cookie')) score += 3;
  if (p.includes('localStorage')) score += 2;
  if (input.browserAlertTriggered) score += 1;
  if (p.includes('%')) score += 1; // WAF bypass encoding
  return score;
}

// ── Severity from total score ───────────────────────────────

const SEVERITY_ORDER: VulnSeverity[] = [
  VulnSeverity.LOW,
  VulnSeverity.MEDIUM,
  VulnSeverity.HIGH,
  VulnSeverity.CRITICAL,
];

function severityIndex(s: VulnSeverity): number {
  return SEVERITY_ORDER.indexOf(s);
}

function severityFromScore(total: number): VulnSeverity {
  if (total >= 8) return VulnSeverity.CRITICAL;
  if (total >= 6) return VulnSeverity.HIGH;
  if (total >= 4) return VulnSeverity.MEDIUM;
  return VulnSeverity.LOW;
}

/** Raise severity to at least `floor` */
function atLeast(current: VulnSeverity, floor: VulnSeverity): VulnSeverity {
  return severityIndex(current) < severityIndex(floor) ? floor : current;
}

/** Cap severity to at most `ceiling` */
function atMost(current: VulnSeverity, ceiling: VulnSeverity): VulnSeverity {
  return severityIndex(current) > severityIndex(ceiling) ? ceiling : current;
}

// ── Override rules ──────────────────────────────────────────

function applyOverrides(
  severity: VulnSeverity,
  input: ScoringInput,
): { severity: VulnSeverity; applied: string[] } {
  let s = severity;
  const applied: string[] = [];
  const src = (input.source ?? '').toLowerCase();
  const sink = (input.sink ?? '').toLowerCase();

  // 1. HASH_SOURCE_LOW_CAP: location.hash source → max LOW
  if (src === 'location.hash' || src === 'hash') {
    const capped = atMost(s, VulnSeverity.LOW);
    if (capped !== s) {
      applied.push('HASH_SOURCE_LOW_CAP');
      s = capped;
    }
  }

  // 2. EVAL_SINK_MINIMUM_HIGH: eval/script sink → min HIGH
  if (sink === 'eval' || sink === 'script') {
    const raised = atLeast(s, VulnSeverity.HIGH);
    if (raised !== s) {
      applied.push('EVAL_SINK_MINIMUM_HIGH');
      s = raised;
    }
  }

  // 3. CONFIRMED_SENSITIVE_EXEC: executed + document.cookie → CRITICAL
  if (input.executed && input.payload.includes('document.cookie')) {
    if (s !== VulnSeverity.CRITICAL) {
      applied.push('CONFIRMED_SENSITIVE_EXEC');
      s = VulnSeverity.CRITICAL;
    }
  }

  // 4. WAF_BYPASS_MEDIUM_MINIMUM: reflected + % + exactMatch → min MEDIUM
  if (input.reflected && input.payload.includes('%') && input.exactMatch) {
    const raised = atLeast(s, VulnSeverity.MEDIUM);
    if (raised !== s) {
      applied.push('WAF_BYPASS_MEDIUM_MINIMUM');
      s = raised;
    }
  }

  // 5. POSTMESSAGE_MEDIUM_MINIMUM: postMessage/e.data source → min MEDIUM
  if (src === 'postmessage' || src === 'e.data') {
    const raised = atLeast(s, VulnSeverity.MEDIUM);
    if (raised !== s) {
      applied.push('POSTMESSAGE_MEDIUM_MINIMUM');
      s = raised;
    }
  }

  return { severity: s, applied };
}

// ── Main scorer ─────────────────────────────────────────────

export function scoreFinding(input: ScoringInput): ScoringResult {
  const execution = getExecutionScore(input);
  const shareability = getShareabilityScore(input);
  const sinkDanger = getSinkDangerScore(input);
  const payload = getPayloadScore(input);
  const total = execution + shareability + sinkDanger + payload;

  const baseSeverity = severityFromScore(total);
  const { severity, applied } = applyOverrides(baseSeverity, input);

  return {
    severity,
    score: total,
    breakdown: { execution, shareability, sinkDanger, payload },
    appliedOverrides: applied,
  };
}

/**
 * Derive sink from reflectionPosition when an explicit sink is not provided
 * by the fuzzer module.
 */
export function deriveSink(reflectionPosition: string, explicitSink?: string): string {
  if (explicitSink) return explicitSink;
  const pos = (reflectionPosition ?? '').toLowerCase();
  if (pos === 'script') return 'script';
  if (pos === 'innerhtml' || pos === 'html_body' || pos === 'body') return 'innerHTML';
  if (pos === 'href') return 'href';
  if (pos === 'attribute') return 'attribute';
  return pos || 'attribute';
}

/**
 * Derive source when an explicit source is not provided.
 * Default assumes URL param (most common for reflected XSS).
 */
export function deriveSource(explicitSource?: string): string {
  if (explicitSource) return explicitSource;
  return 'URLSearchParams';
}
