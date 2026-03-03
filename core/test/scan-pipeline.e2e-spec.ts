/**
 * integration test — scan processor pipeline
 * tests the full 5-phase scan pipeline with mocked external deps:
 *   crawlerService (mocked), python modules (nock http), reportService (mocked).
 * verifies status transitions, websocket events, vuln accumulation.
 */

import { Test, TestingModule } from '@nestjs/testing';
import nock from 'nock';
import { ScanProcessor } from '../src/queue/scan.processor';
import { ScanService } from '../src/scan/scan.service';
import { ScanGateway } from '../src/scan/scan.gateway';
import { CrawlerService } from '../src/crawler/crawler.service';
import { ContextClientService } from '../src/modules-bridge/context-client.service';
import { PayloadClientService } from '../src/modules-bridge/payload-client.service';
import { FuzzerClientService } from '../src/modules-bridge/fuzzer-client.service';
import { ReportService } from '../src/report/report.service';
import { ScanStatus, ScanPhase } from '../src/common/interfaces/scan.interface';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanEntity } from '../src/scan/entities/scan.entity';
import { VulnEntity } from '../src/scan/entities/vuln.entity';

describe('scan processor pipeline (integration)', () => {
  let processor: ScanProcessor;
  let scanService: ScanService;
  let gateway: ScanGateway;

  const CONTEXT_URL = 'http://localhost:5001';
  const PAYLOAD_GEN_URL = 'http://localhost:5002';
  const FUZZER_URL = 'http://localhost:5003';

  const mockCrawler = {
    crawl: jest.fn(),
  };

  const mockReportService = {
    buildVuln: jest.fn(),
    generate: jest.fn().mockResolvedValue('/reports/test.html'),
  };

  const mockGateway = {
    server: { emit: jest.fn() },
    emitProgress: jest.fn(),
    emitFinding: jest.fn(),
    emitComplete: jest.fn(),
    emitError: jest.fn(),
  };

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [
            () => ({
              CONTEXT_URL,
              PAYLOAD_GEN_URL,
              FUZZER_URL,
            }),
          ],
        }),
        TypeOrmModule.forRoot({
          type: 'better-sqlite3',
          database: ':memory:',
          entities: [ScanEntity, VulnEntity],
          synchronize: true,
        }),
        TypeOrmModule.forFeature([ScanEntity, VulnEntity]),
        HttpModule,
      ],
      providers: [
        ScanService,
        ContextClientService,
        PayloadClientService,
        FuzzerClientService,
        { provide: CrawlerService, useValue: mockCrawler },
        { provide: ReportService, useValue: mockReportService },
        { provide: ScanGateway, useValue: mockGateway },
      ],
    }).compile();

    scanService = moduleFixture.get(ScanService);
    gateway = moduleFixture.get(ScanGateway);

    // manually create the processor — it extends WorkerHost which needs
    // bullmq runtime, so we construct it directly
    processor = new ScanProcessor(
      scanService,
      gateway as unknown as ScanGateway,
      mockCrawler as unknown as CrawlerService,
      moduleFixture.get(ContextClientService),
      moduleFixture.get(PayloadClientService),
      moduleFixture.get(FuzzerClientService),
      mockReportService as unknown as ReportService,
    );
  });

  afterEach(() => {
    nock.cleanAll();
    jest.clearAllMocks();
  });

  afterAll(() => {
    nock.restore();
  });

  function setupCrawlResult() {
    mockCrawler.crawl.mockResolvedValue({
      baseUrl: 'https://target.com',
      urls: ['https://target.com', 'https://target.com/search'],
      params: [
        { name: 'q', source: 'query', method: 'GET' },
        { name: 'page', source: 'query', method: 'GET' },
      ],
      forms: [],
      domSinks: [],
      waf: { detected: false, name: null, confidence: 0 },
      durationMs: 1200,
    });
  }

  function setupContextMock() {
    return nock(CONTEXT_URL)
      .post('/analyze')
      .reply(200, {
        q: {
          reflects_in: 'html_text',
          allowed_chars: ['<', '>', '"', "'"],
          context_confidence: 0.92,
        },
        page: {
          reflects_in: 'none',
          allowed_chars: [],
          context_confidence: 0,
        },
      });
  }

  function setupPayloadGenMock() {
    return nock(PAYLOAD_GEN_URL)
      .post('/generate')
      .reply(200, {
        payloads: [
          {
            payload: '<script>alert(1)</script>',
            target_param: 'q',
            context: 'html_text',
            confidence: 0.95,
            waf_bypass: false,
          },
          {
            payload: '<img src=x onerror=alert(1)>',
            target_param: 'q',
            context: 'html_text',
            confidence: 0.88,
            waf_bypass: false,
          },
        ],
      });
  }

  function setupFuzzerMock(vulnCount: number) {
    const results = [
      {
        payload: '<script>alert(1)</script>',
        target_param: 'q',
        reflected: true,
        executed: true,
        vuln: true,
        type: 'reflected_xss',
        evidence: {
          response_code: 200,
          reflection_position: 'body',
          browser_alert_triggered: true,
        },
      },
      {
        payload: '<img src=x onerror=alert(1)>',
        target_param: 'q',
        reflected: true,
        executed: false,
        vuln: false,
        type: 'reflected_xss',
        evidence: {
          response_code: 200,
          reflection_position: 'body',
          browser_alert_triggered: false,
        },
      },
    ];

    return nock(FUZZER_URL)
      .post('/test')
      .reply(200, { results: results.slice(0, vulnCount === 0 ? 0 : 2) });
  }

  function createMockJob(scanId: string) {
    return {
      data: { scanId },
      id: 'job-1',
      updateProgress: jest.fn(),
    } as any;
  }

  it('runs full pipeline: crawl → context → payloads → fuzz → report', async () => {
    const scan = await scanService.create({ url: 'https://target.com' });
    setupCrawlResult();
    const contextScope = setupContextMock();
    const payloadScope = setupPayloadGenMock();
    const fuzzerScope = setupFuzzerMock(1);

    mockReportService.buildVuln.mockReturnValue({
      id: 'vuln-1',
      scanId: scan.id,
      param: 'q',
      payload: '<script>alert(1)</script>',
      type: 'reflected_xss',
      severity: 'HIGH',
      url: 'https://target.com',
      reflected: true,
      executed: true,
      evidence: {
        responseCode: 200,
        reflectionPosition: 'body',
        browserAlertTriggered: true,
      },
      discoveredAt: new Date(),
    });

    await processor.process(createMockJob(scan.id));

    // all python modules were called
    expect(contextScope.isDone()).toBe(true);
    expect(payloadScope.isDone()).toBe(true);
    expect(fuzzerScope.isDone()).toBe(true);

    // crawler was called
    expect(mockCrawler.crawl).toHaveBeenCalledWith('https://target.com', 3, 100);

    // scan ended in DONE status
    const final = await scanService.findOne(scan.id);
    expect(final.status).toBe(ScanStatus.DONE);
    expect(final.phase).toBe(ScanPhase.REPORT);
    expect(final.progress).toBe(100);
    expect(final.completedAt).toBeDefined();

    // vulns were accumulated
    const vulns = await scanService.getVulns(scan.id);
    expect(vulns.length).toBe(1);
    expect(vulns[0].param).toBe('q');

    // report was generated
    expect(mockReportService.generate).toHaveBeenCalledWith(
      scan.id,
      expect.objectContaining({ url: 'https://target.com' }),
      vulns,
      ['html', 'json'],
    );

    // websocket events were emitted
    expect(mockGateway.emitProgress).toHaveBeenCalled();
    expect(mockGateway.emitFinding).toHaveBeenCalled();
    expect(mockGateway.emitComplete).toHaveBeenCalledWith(
      expect.objectContaining({
        scanId: scan.id,
        summary: expect.objectContaining({
          totalParams: 2,
          paramsTested: 2,
          vulnsFound: 1,
        }),
        reportUrl: '/reports/test.html',
      }),
    );
  });

  it('emits correct phase progression events', async () => {
    const scan = await scanService.create({ url: 'https://phase-test.com' });
    setupCrawlResult();
    setupContextMock();
    setupPayloadGenMock();
    setupFuzzerMock(0);

    await processor.process(createMockJob(scan.id));

    const progressCalls = mockGateway.emitProgress.mock.calls.map(
      (c: any[]) => c[0],
    );
    const phases = progressCalls.map((p: any) => p.phase);

    expect(phases).toContain(ScanPhase.CRAWL);
    expect(phases).toContain(ScanPhase.CONTEXT);
    expect(phases).toContain(ScanPhase.PAYLOAD_GEN);
    expect(phases).toContain(ScanPhase.FUZZ);

    // progress should increase monotonically
    const progressValues = progressCalls.map((p: any) => p.progress);
    for (let i = 1; i < progressValues.length; i++) {
      expect(progressValues[i]).toBeGreaterThanOrEqual(progressValues[i - 1]);
    }
  });

  it('marks scan as failed when context module errors', async () => {
    const scan = await scanService.create({ url: 'https://fail-test.com' });
    setupCrawlResult();

    nock(CONTEXT_URL).post('/analyze').reply(500, { detail: 'ai model crashed' });

    await expect(processor.process(createMockJob(scan.id))).rejects.toThrow();

    const failed = await scanService.findOne(scan.id);
    expect(failed.status).toBe(ScanStatus.FAILED);
    expect(failed.error).toBeDefined();
    expect(mockGateway.emitError).toHaveBeenCalledWith(
      scan.id,
      expect.stringContaining('context'),
    );
  });

  it('marks scan as failed when fuzzer module errors', async () => {
    const scan = await scanService.create({ url: 'https://fuzzer-fail.com' });
    setupCrawlResult();
    setupContextMock();
    setupPayloadGenMock();

    nock(FUZZER_URL).post('/test').reply(500, { detail: 'browser timeout' });

    await expect(processor.process(createMockJob(scan.id))).rejects.toThrow();

    const failed = await scanService.findOne(scan.id);
    expect(failed.status).toBe(ScanStatus.FAILED);
    expect(mockGateway.emitError).toHaveBeenCalledWith(
      scan.id,
      expect.stringContaining('fuzzer'),
    );
  });

  it('marks scan as failed when crawler errors', async () => {
    const scan = await scanService.create({ url: 'https://crawl-fail.com' });
    mockCrawler.crawl.mockRejectedValue(new Error('chromium crashed'));

    await expect(processor.process(createMockJob(scan.id))).rejects.toThrow();

    const failed = await scanService.findOne(scan.id);
    expect(failed.status).toBe(ScanStatus.FAILED);
    expect(failed.error).toContain('chromium crashed');
  });

  it('handles zero vulns — clean scan', async () => {
    const scan = await scanService.create({ url: 'https://safe-site.com' });
    setupCrawlResult();
    setupContextMock();
    setupPayloadGenMock();

    nock(FUZZER_URL).post('/test').reply(200, {
      results: [
        {
          payload: '<script>alert(1)</script>',
          target_param: 'q',
          reflected: false,
          executed: false,
          vuln: false,
          type: 'reflected_xss',
          evidence: {
            response_code: 200,
            reflection_position: '',
            browser_alert_triggered: false,
          },
        },
      ],
    });

    await processor.process(createMockJob(scan.id));

    const final = await scanService.findOne(scan.id);
    expect(final.status).toBe(ScanStatus.DONE);
    expect((await scanService.getVulns(scan.id)).length).toBe(0);

    // emitFinding should NOT have been called
    expect(mockGateway.emitFinding).not.toHaveBeenCalled();

    // emitComplete should show 0 vulns
    expect(mockGateway.emitComplete).toHaveBeenCalledWith(
      expect.objectContaining({
        summary: expect.objectContaining({ vulnsFound: 0 }),
      }),
    );
  });
});
