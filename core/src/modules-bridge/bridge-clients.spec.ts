import { of, throwError } from 'rxjs';
import { ContextClientService } from './context-client.service';
import { PayloadClientService } from './payload-client.service';
import { FuzzerClientService } from './fuzzer-client.service';
import { PythonModuleException } from '../common/exceptions/scan.exceptions';

/* ── helpers ──────────────────────────────────────────────── */

function mockConfig(overrides: Record<string, string> = {}) {
  return {
    get: jest.fn((key: string, fallback?: string) => overrides[key] ?? fallback),
  } as any;
}

function mockHttp(response: any) {
  return {
    post: jest.fn(() => of({ data: response })),
    get: jest.fn(() => of({ data: response })),
  } as any;
}

function mockHttpError(msg: string) {
  return {
    post: jest.fn(() => throwError(() => new Error(msg))),
  } as any;
}

/* ── ContextClientService ─────────────────────────────────── */

describe('ContextClientService', () => {
  it('calls POST /analyze and returns context map', async () => {
    const resp = { q: { reflects_in: 'html_text', allowed_chars: ['<', '>'], context_confidence: 0.9 } };
    const http = mockHttp(resp);
    const svc = new ContextClientService(http, mockConfig());
    const result = await svc.analyze({ url: 'https://t.com', params: ['q'], waf: 'none' });
    expect(http.post).toHaveBeenCalledWith('http://localhost:5001/analyze', expect.anything());
    expect(result.q.reflects_in).toBe('html_text');
  });

  it('uses configured CONTEXT_URL', async () => {
    const http = mockHttp({});
    const svc = new ContextClientService(http, mockConfig({ CONTEXT_URL: 'http://ctx:9000' }));
    await svc.analyze({ url: 'https://t.com', params: ['q'], waf: 'none' });
    expect(http.post).toHaveBeenCalledWith('http://ctx:9000/analyze', expect.anything());
  });

  it('throws PythonModuleException on error', async () => {
    const http = mockHttpError('network fail');
    const svc = new ContextClientService(http, mockConfig());
    await expect(svc.analyze({ url: 'https://t.com', params: ['q'], waf: 'none' }))
      .rejects.toThrow(PythonModuleException);
  });
});

/* ── PayloadClientService ─────────────────────────────────── */

describe('PayloadClientService', () => {
  it('calls POST /generate and returns payloads', async () => {
    const resp = { payloads: [{ payload: '<img src=x>', target_param: 'q', context: 'html_text', confidence: 0.8, waf_bypass: false }] };
    const http = mockHttp(resp);
    const svc = new PayloadClientService(http, mockConfig());
    const result = await svc.generate({ contexts: {}, waf: 'none', maxPayloads: 10 });
    expect(http.post).toHaveBeenCalledWith(
      'http://localhost:5002/generate',
      expect.objectContaining({ max_payloads: 10 }),
    );
    expect(result.payloads).toHaveLength(1);
  });

  it('remaps maxPayloads to max_payloads for Python API', async () => {
    const http = mockHttp({ payloads: [] });
    const svc = new PayloadClientService(http, mockConfig());
    await svc.generate({ contexts: {}, waf: 'none', maxPayloads: 25 });
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.max_payloads).toBe(25);
    expect(postBody.maxPayloads).toBeUndefined();
  });

  it('throws PythonModuleException on error', async () => {
    const http = mockHttpError('timeout');
    const svc = new PayloadClientService(http, mockConfig());
    await expect(svc.generate({ contexts: {}, waf: 'none', maxPayloads: 10 }))
      .rejects.toThrow(PythonModuleException);
  });
});

/* ── FuzzerClientService ──────────────────────────────────── */

describe('FuzzerClientService', () => {
  it('calls POST /test and returns results', async () => {
    const resp = { results: [{ payload: '<script>', target_param: 'q', reflected: true, executed: false, vuln: false, type: '', evidence: {} }] };
    const http = mockHttp(resp);
    const svc = new FuzzerClientService(http, mockConfig());
    const result = await svc.test({ url: 'https://t.com', payloads: [], verifyExecution: true, timeout: 5000 });
    expect(http.post).toHaveBeenCalledWith(
      'http://localhost:5003/test',
      expect.objectContaining({ verify_execution: true }),
    );
    expect(result.results).toHaveLength(1);
  });

  it('remaps verifyExecution to verify_execution for Python API', async () => {
    const http = mockHttp({ results: [] });
    const svc = new FuzzerClientService(http, mockConfig());
    await svc.test({ url: 'https://t.com', payloads: [], verifyExecution: false, timeout: 3000 });
    const postBody = http.post.mock.calls[0][1];
    expect(postBody.verify_execution).toBe(false);
  });

  it('throws PythonModuleException on error', async () => {
    const http = mockHttpError('connection refused');
    const svc = new FuzzerClientService(http, mockConfig());
    await expect(svc.test({ url: 'https://t.com', payloads: [], verifyExecution: true, timeout: 5000 }))
      .rejects.toThrow(PythonModuleException);
  });
});
