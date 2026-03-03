import {
  scoreFinding,
  getExecutionScore,
  getShareabilityScore,
  getSinkDangerScore,
  getPayloadScore,
  deriveSink,
  deriveSource,
  ScoringInput,
} from './severity-scorer';
import { VulnSeverity } from '../interfaces/vuln.interface';

function makeInput(overrides: Partial<ScoringInput> = {}): ScoringInput {
  return {
    reflected: true,
    executed: false,
    payload: '<script>alert(1)</script>',
    source: 'url_param',
    sink: 'attribute',
    exactMatch: true,
    browserAlertTriggered: false,
    ...overrides,
  };
}

describe('severity-scorer', () => {
  // ── Execution score ───────────────────────────────────────
  describe('getExecutionScore', () => {
    it('returns 3 for executed', () => {
      expect(getExecutionScore(makeInput({ executed: true }))).toBe(3);
    });
    it('returns 2 for reflected only', () => {
      expect(getExecutionScore(makeInput({ reflected: true, executed: false }))).toBe(2);
    });
    it('returns 1 for dom-only (neither reflected nor executed)', () => {
      expect(getExecutionScore(makeInput({ reflected: false, executed: false }))).toBe(1);
    });
  });

  // ── Shareability score ────────────────────────────────────
  describe('getShareabilityScore', () => {
    it('returns 3 for url_param', () => {
      expect(getShareabilityScore(makeInput({ source: 'url_param' }))).toBe(3);
    });
    it('returns 3 for empty source (default = url_param)', () => {
      expect(getShareabilityScore(makeInput({ source: '' }))).toBe(3);
    });
    it('returns 1 for URLSearchParams (client-side JS source)', () => {
      expect(getShareabilityScore(makeInput({ source: 'URLSearchParams' }))).toBe(1);
    });
    it('returns 2 for postMessage', () => {
      expect(getShareabilityScore(makeInput({ source: 'postMessage' }))).toBe(2);
    });
    it('returns 2 for e.data', () => {
      expect(getShareabilityScore(makeInput({ source: 'e.data' }))).toBe(2);
    });
    it('returns 1 for location.hash', () => {
      expect(getShareabilityScore(makeInput({ source: 'location.hash' }))).toBe(1);
    });
    it('returns 1 for document.cookie', () => {
      expect(getShareabilityScore(makeInput({ source: 'document.cookie' }))).toBe(1);
    });
    it('returns 1 for unknown source (conservative)', () => {
      expect(getShareabilityScore(makeInput({ source: 'window.name' }))).toBe(1);
    });
  });

  // ── Sink danger score ─────────────────────────────────────
  describe('getSinkDangerScore', () => {
    it('returns 3 for eval', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'eval' }))).toBe(3);
    });
    it('returns 3 for script context', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'script' }))).toBe(3);
    });
    it('returns 3 for document.write', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'document.write' }))).toBe(3);
    });
    it('returns 3 for location_assign', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'location_assign' }))).toBe(3);
    });
    it('returns 2 for innerHTML', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'innerHTML' }))).toBe(2);
    });
    it('returns 2 for html_body', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'html_body' }))).toBe(2);
    });
    it('returns 2 for comment', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'comment' }))).toBe(2);
    });
    it('returns 2 for jQuery_html', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'jQuery_html' }))).toBe(2);
    });
    it('returns 1 for attribute', () => {
      expect(getSinkDangerScore(makeInput({ sink: 'attribute' }))).toBe(1);
    });
  });

  // ── Payload score ─────────────────────────────────────────
  describe('getPayloadScore', () => {
    it('returns 3 for document.cookie in payload', () => {
      expect(getPayloadScore(makeInput({ payload: 'x(document.cookie)' }))).toBe(3);
    });
    it('returns 2 for localStorage in payload', () => {
      expect(getPayloadScore(makeInput({ payload: 'localStorage.getItem("x")' }))).toBe(2);
    });
    it('returns 1 for % (WAF bypass) in payload', () => {
      expect(getPayloadScore(makeInput({ payload: '<%00script>' }))).toBe(1);
    });
    it('returns 1 for browserAlertTriggered', () => {
      expect(getPayloadScore(makeInput({ payload: 'x', browserAlertTriggered: true }))).toBe(1);
    });
    it('stacks document.cookie + %', () => {
      expect(getPayloadScore(makeInput({ payload: '%27(document.cookie)' }))).toBe(4);
    });
    it('returns 0 for clean payload', () => {
      expect(getPayloadScore(makeInput({ payload: '<img src=x onerror=alert(1)>' }))).toBe(0);
    });
    it('returns 0 for DOM-XSS taint descriptions (not real payloads)', () => {
      expect(getPayloadScore(makeInput({
        payload: 'DOM-XSS: innerHTML <- document.cookie',
      }))).toBe(0);
    });
    it('returns 0 for DOM-XSS taint with URLSearchParams', () => {
      expect(getPayloadScore(makeInput({
        payload: 'DOM-XSS: eval <- URLSearchParams',
      }))).toBe(0);
    });
  });

  // ── Full scoring (matrix → severity) ─────────────────────
  describe('scoreFinding', () => {
    it('reflected + URL param + attribute → 6 → HIGH', () => {
      const r = scoreFinding(makeInput());
      // exec=2 + share=3 + sink=1 + payload=0 = 6
      expect(r.score).toBe(6);
      expect(r.severity).toBe(VulnSeverity.HIGH);
    });

    it('reflected + URL param + script → 8 → CRITICAL', () => {
      const r = scoreFinding(makeInput({ sink: 'script' }));
      // exec=2 + share=3 + sink=3 + payload=0 = 8
      expect(r.score).toBe(8);
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
    });

    it('reflected + URL param + innerHTML → 7 → HIGH', () => {
      const r = scoreFinding(makeInput({ sink: 'innerHTML' }));
      // exec=2 + share=3 + sink=2 + payload=0 = 7
      expect(r.score).toBe(7);
      expect(r.severity).toBe(VulnSeverity.HIGH);
    });

    it('reflected + URL param + attribute + document.cookie → 9 → CRITICAL', () => {
      const r = scoreFinding(makeInput({ payload: 'x(document.cookie)' }));
      // exec=2 + share=3 + sink=1 + payload=3 = 9
      expect(r.score).toBe(9);
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
    });

    it('reflected + URL param + attribute + % → 7 → HIGH', () => {
      const r = scoreFinding(makeInput({ payload: '<%00iframe>' }));
      // exec=2 + share=3 + sink=1 + payload=1 = 7
      expect(r.score).toBe(7);
      expect(r.severity).toBe(VulnSeverity.HIGH);
    });

    it('dom-only + hash + attribute → 3 → LOW', () => {
      const r = scoreFinding(makeInput({
        reflected: false,
        executed: false,
        source: 'location.hash',
        sink: 'attribute',
        payload: 'x',
      }));
      // exec=1 + share=1 + sink=1 + payload=0 = 3
      expect(r.score).toBe(3);
      expect(r.severity).toBe(VulnSeverity.LOW);
    });
  });

  // ── Override rules ────────────────────────────────────────
  describe('override rules', () => {
    it('HASH_SOURCE_LOW_CAP: caps hash + script to LOW (EVAL override no longer fires for script)', () => {
      // hash + script: score=2+1+3+0=6 → HIGH base
      // Rule 1 (HASH_SOURCE_LOW_CAP) caps to LOW
      // Rule 2 (EVAL_SINK_MINIMUM_HIGH) does NOT fire for script anymore (only eval)
      const r = scoreFinding(makeInput({
        source: 'location.hash',
        sink: 'script',
      }));
      expect(r.severity).toBe(VulnSeverity.LOW);
      expect(r.appliedOverrides).toContain('HASH_SOURCE_LOW_CAP');
      expect(r.appliedOverrides).not.toContain('EVAL_SINK_MINIMUM_HIGH');
    });

    it('HASH_SOURCE_LOW_CAP: hash + eval → LOW capped then EVAL raises to HIGH', () => {
      // hash + eval: score=2+1+3+0=6 → HIGH base
      // Rule 1 caps to LOW, Rule 2 raises back to HIGH
      const r = scoreFinding(makeInput({
        source: 'location.hash',
        sink: 'eval',
      }));
      expect(r.severity).toBe(VulnSeverity.HIGH);
      expect(r.appliedOverrides).toContain('HASH_SOURCE_LOW_CAP');
      expect(r.appliedOverrides).toContain('EVAL_SINK_MINIMUM_HIGH');
    });

    it('HASH_SOURCE_LOW_CAP: caps hash + attribute to LOW', () => {
      const r = scoreFinding(makeInput({
        source: 'location.hash',
        sink: 'attribute',
        payload: 'x',
      }));
      // exec=2 + share=1 + sink=1 + payload=0 = 4 → MEDIUM base
      // Rule 1 caps to LOW
      expect(r.severity).toBe(VulnSeverity.LOW);
      expect(r.appliedOverrides).toContain('HASH_SOURCE_LOW_CAP');
    });

    it('EVAL_SINK_MINIMUM_HIGH: raises eval sink to min HIGH', () => {
      // dom-only + URLSearchParams + eval → score=1+1+3+0=5 → MEDIUM, override → HIGH
      const r = scoreFinding(makeInput({
        reflected: false,
        executed: false,
        source: 'URLSearchParams',
        sink: 'eval',
        payload: 'x',
      }));
      expect(r.score).toBe(5);
      expect(r.severity).toBe(VulnSeverity.HIGH);
      expect(r.appliedOverrides).toContain('EVAL_SINK_MINIMUM_HIGH');
    });

    it('EVAL_SINK_MINIMUM_HIGH: does NOT fire for script sink', () => {
      // dom-only + e.data + script → score=1+2+3+0=6 → HIGH from score alone
      const r2 = scoreFinding(makeInput({
        reflected: false,
        executed: false,
        source: 'e.data',
        sink: 'script',
        payload: 'x',
      }));
      expect(r2.severity).toBe(VulnSeverity.HIGH);
      expect(r2.appliedOverrides).not.toContain('EVAL_SINK_MINIMUM_HIGH');
    });

    it('CONFIRMED_SENSITIVE_EXEC: executed + document.cookie → CRITICAL', () => {
      // Use a low-scoring setup so CRITICAL comes from override, not base score
      const r = scoreFinding(makeInput({
        executed: true,
        reflected: false,
        payload: 'fetch("x?c="+document.cookie)',
        sink: 'attribute',
        source: 'e.data',
      }));
      // exec=3 + share=2 + sink=1 + payload=3 = 9 → already CRITICAL from score
      // Override also fires but severity is already CRITICAL
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
    });

    it('CONFIRMED_SENSITIVE_EXEC: overrides lower score to CRITICAL', () => {
      // Setup where base score = MEDIUM but override pushes to CRITICAL
      const r = scoreFinding(makeInput({
        executed: true,
        reflected: false,
        payload: 'document.cookie',
        sink: 'attribute',
        source: 'location.hash',
      }));
      // exec=3 + share=1 + sink=1 + payload=3 = 8 → CRITICAL base
      // hash caps to LOW → then CONFIRMED_SENSITIVE_EXEC → CRITICAL
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
      expect(r.appliedOverrides).toContain('CONFIRMED_SENSITIVE_EXEC');
    });

    it('WAF_BYPASS_MEDIUM_MINIMUM: reflected + % + exactMatch → min MEDIUM', () => {
      // Need a case where base score < MEDIUM: dom-only + hash + attribute
      // But hash cap overrides to LOW anyway...
      // Test with a setup that gives LOW without hash
      const r = scoreFinding(makeInput({
        reflected: true,
        executed: false,
        source: 'location.hash',
        sink: 'attribute',
        payload: '<%00x>',
        exactMatch: true,
      }));
      // Score: 2+1+1+1=5 → MEDIUM base, hash caps to LOW, then WAF raises to MEDIUM
      expect(r.appliedOverrides).toContain('HASH_SOURCE_LOW_CAP');
      expect(r.appliedOverrides).toContain('WAF_BYPASS_MEDIUM_MINIMUM');
      expect(r.severity).toBe(VulnSeverity.MEDIUM);
    });

    it('POSTMESSAGE_MEDIUM_MINIMUM: postMessage source → min MEDIUM', () => {
      const r = scoreFinding(makeInput({
        reflected: false,
        executed: false,
        source: 'postMessage',
        sink: 'attribute',
        payload: 'x',
      }));
      // exec=1 + share=2 + sink=1 + payload=0 = 4 → MEDIUM
      expect(r.score).toBe(4);
      expect(r.severity).toBe(VulnSeverity.MEDIUM);
    });
  });

  // ── deriveSink / deriveSource ─────────────────────────────
  describe('deriveSink', () => {
    it('returns explicit sink when provided', () => {
      expect(deriveSink('body', 'eval')).toBe('eval');
    });
    it('maps body → innerHTML', () => {
      expect(deriveSink('body')).toBe('innerHTML');
    });
    it('maps html_body → innerHTML', () => {
      expect(deriveSink('html_body')).toBe('innerHTML');
    });
    it('maps script → script', () => {
      expect(deriveSink('script')).toBe('script');
    });
    it('maps attribute → attribute', () => {
      expect(deriveSink('attribute')).toBe('attribute');
    });
    it('defaults to attribute when empty', () => {
      expect(deriveSink('')).toBe('attribute');
    });
  });

  describe('deriveSource', () => {
    it('returns explicit source when provided', () => {
      expect(deriveSource('location.hash')).toBe('location.hash');
    });
    it('defaults to url_param (reflected XSS default)', () => {
      expect(deriveSource()).toBe('url_param');
      expect(deriveSource(undefined)).toBe('url_param');
    });
  });

  // ── Real findings from the bug report ─────────────────────
  describe('real findings regression', () => {
    it('Finding 1: /body reflected+url_param+attribute+% → HIGH', () => {
      const r = scoreFinding({
        reflected: true, executed: false,
        source: 'url_param', sink: 'attribute',
        payload: '<a href="javascript://%0aself.alert(1)">XSS</a>',
        exactMatch: true, browserAlertTriggered: false,
      });
      expect(r.severity).toBe(VulnSeverity.HIGH);
    });

    it('Finding 4: /script reflected+url_param+script → CRITICAL', () => {
      const r = scoreFinding({
        reflected: true, executed: false,
        source: 'url_param', sink: 'script',
        payload: "$eval('x=alert(1)//');",
        exactMatch: true, browserAlertTriggered: false,
      });
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
    });

    it('Finding 6: /href reflected+url_param+attribute+document.cookie → CRITICAL', () => {
      const r = scoreFinding({
        reflected: true, executed: false,
        source: 'url_param', sink: 'attribute',
        payload: 'window.name="javascript:alert`1`.document.cookie);";',
        exactMatch: true, browserAlertTriggered: false,
      });
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
    });

    it('Finding 8: /textarea reflected+url_param+innerHTML → HIGH', () => {
      const r = scoreFinding({
        reflected: true, executed: false,
        source: 'url_param', sink: 'innerHTML',
        payload: '<meter src="#\\nalert(1)" codebase=javascript://>',
        exactMatch: true, browserAlertTriggered: false,
      });
      expect(r.severity).toBe(VulnSeverity.HIGH);
    });

    it('Finding 9: /comment reflected+url_param+attribute+cookie+% → CRITICAL', () => {
      const r = scoreFinding({
        reflected: true, executed: false,
        source: 'url_param', sink: 'attribute',
        payload: "<!--><svg+onmouseover=%27top[%2fal%2f...](document.cookie)%27>",
        exactMatch: true, browserAlertTriggered: false,
      });
      expect(r.severity).toBe(VulnSeverity.CRITICAL);
    });

    // ── DOM XSS findings regression ─────────────────────────
    it('DOM Finding 4: dom-only+URLSearchParams+document.write → MEDIUM', () => {
      const r = scoreFinding({
        reflected: false, executed: false,
        source: 'URLSearchParams', sink: 'document.write',
        payload: 'DOM-XSS: document.write <- URLSearchParams',
        exactMatch: false, browserAlertTriggered: false,
      });
      // exec=1 + share=1 + sink=3 + payload=0(DOM-XSS prefix) = 5 → MEDIUM
      expect(r.score).toBe(5);
      expect(r.severity).toBe(VulnSeverity.MEDIUM);
    });

    it('DOM Finding 5: dom-only+URLSearchParams+innerHTML → MEDIUM', () => {
      const r = scoreFinding({
        reflected: false, executed: false,
        source: 'URLSearchParams', sink: 'innerHTML',
        payload: 'DOM-XSS: innerHTML <- URLSearchParams',
        exactMatch: false, browserAlertTriggered: false,
      });
      // exec=1 + share=1 + sink=2 + payload=0 = 4 → MEDIUM
      expect(r.score).toBe(4);
      expect(r.severity).toBe(VulnSeverity.MEDIUM);
    });

    it('DOM Finding 8: dom-only+URLSearchParams+eval → HIGH (EVAL override)', () => {
      const r = scoreFinding({
        reflected: false, executed: false,
        source: 'URLSearchParams', sink: 'eval',
        payload: 'DOM-XSS: eval <- URLSearchParams',
        exactMatch: false, browserAlertTriggered: false,
      });
      // exec=1 + share=1 + sink=3 + payload=0 = 5 → MEDIUM, override → HIGH
      expect(r.score).toBe(5);
      expect(r.severity).toBe(VulnSeverity.HIGH);
      expect(r.appliedOverrides).toContain('EVAL_SINK_MINIMUM_HIGH');
    });

    it('DOM Finding 17: dom-only+document.cookie+innerHTML → MEDIUM', () => {
      const r = scoreFinding({
        reflected: false, executed: false,
        source: 'document.cookie', sink: 'innerHTML',
        payload: 'DOM-XSS: innerHTML <- document.cookie',
        exactMatch: false, browserAlertTriggered: false,
      });
      // exec=1 + share=1 + sink=2 + payload=0(DOM-XSS prefix stops scoring) = 4 → MEDIUM
      expect(r.score).toBe(4);
      expect(r.severity).toBe(VulnSeverity.MEDIUM);
    });

    it('DOM Finding 2: executed+URLSearchParams+comment+alert → HIGH', () => {
      const r = scoreFinding({
        reflected: false, executed: true,
        source: 'URLSearchParams', sink: 'comment',
        payload: '<svg onload=alert()>',
        exactMatch: false, browserAlertTriggered: true,
      });
      // exec=3 + share=1 + sink=2 + payload=1(alert) = 7 → HIGH
      expect(r.score).toBe(7);
      expect(r.severity).toBe(VulnSeverity.HIGH);
    });

    it('DOM Finding 20: dom-only+hash+document.write → LOW (hash cap)', () => {
      const r = scoreFinding({
        reflected: false, executed: false,
        source: 'location.hash', sink: 'document.write',
        payload: 'DOM-XSS: document.write <- location.hash',
        exactMatch: false, browserAlertTriggered: false,
      });
      // exec=1 + share=1 + sink=3 + payload=0 = 5 → MEDIUM, hash cap → LOW
      expect(r.score).toBe(5);
      expect(r.severity).toBe(VulnSeverity.LOW);
      expect(r.appliedOverrides).toContain('HASH_SOURCE_LOW_CAP');
    });
  });
});
