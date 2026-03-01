import * as fs from 'fs';
import * as path from 'path';
import { ReportService } from './report.service';
import { ScanStatus } from '../common/interfaces/scan.interface';
import { VulnType, VulnSeverity } from '../common/interfaces/vuln.interface';

jest.mock('puppeteer', () => ({
  launch: jest.fn(),
}));

describe('ReportService', () => {
  let service: ReportService;
  const reportsDir = path.join(process.cwd(), 'reports');

  beforeEach(() => {
    service = new ReportService();
  });

  afterAll(async () => {
    await service.onModuleDestroy();
  });

  describe('buildVuln', () => {
    it('maps FuzzResult to Vuln with correct fields', () => {
      const result = {
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
      };
      const vuln = service.buildVuln('scan-1', 'https://t.com', result);
      expect(vuln.id).toBeDefined();
      expect(vuln.scanId).toBe('scan-1');
      expect(vuln.url).toBe('https://t.com');
      expect(vuln.param).toBe('q');
      expect(vuln.payload).toBe('<script>alert(1)</script>');
      expect(vuln.reflected).toBe(true);
      expect(vuln.executed).toBe(true);
    });

    it('assigns HIGH severity when browser alert triggered', () => {
      const result = {
        payload: '<img onerror=alert(1)>',
        target_param: 'p',
        reflected: true,
        executed: true,
        vuln: true,
        type: 'reflected_xss',
        evidence: {
          response_code: 200,
          reflection_position: 'body',
          browser_alert_triggered: true,
        },
      };
      expect(service.buildVuln('s1', 'https://t.com', result).severity)
        .toBe(VulnSeverity.HIGH);
    });

    it('assigns MEDIUM severity when browser alert not triggered', () => {
      const result = {
        payload: '<img src=x>',
        target_param: 'p',
        reflected: true,
        executed: false,
        vuln: false,
        type: 'reflected_xss',
        evidence: {
          response_code: 200,
          reflection_position: 'body',
          browser_alert_triggered: false,
        },
      };
      expect(service.buildVuln('s1', 'https://t.com', result).severity)
        .toBe(VulnSeverity.MEDIUM);
    });
  });

  describe('getAvailableFormats', () => {
    it('returns empty array when no reports exist', () => {
      const formats = service.getAvailableFormats('nonexistent-scan');
      expect(formats).toEqual([]);
    });
  });

  describe('getReportPath', () => {
    it('returns null when report file does not exist', () => {
      expect(service.getReportPath('nonexistent', 'html')).toBeNull();
    });
  });

  describe('generate (json only)', () => {
    const scanId = 'test-gen-json';
    const scan = {
      id: scanId,
      url: 'https://target.com',
      status: ScanStatus.DONE,
      progress: 100,
      options: { depth: 3, maxParams: 100, verifyExecution: true, wafBypass: true, maxPayloadsPerParam: 50, timeout: 60000, reportFormat: ['json'] as ('html' | 'json' | 'pdf')[] },
      createdAt: new Date('2025-01-01'),
      updatedAt: new Date('2025-01-01'),
      completedAt: new Date('2025-01-01T00:05:00'),
    };
    const vulns = [
      {
        id: 'v1',
        scanId,
        url: 'https://target.com',
        param: 'q',
        payload: '<script>alert(1)</script>',
        type: VulnType.REFLECTED_XSS,
        severity: VulnSeverity.HIGH,
        reflected: true,
        executed: true,
        evidence: { responseCode: 200, reflectionPosition: 'body', browserAlertTriggered: true },
        discoveredAt: new Date('2025-01-01T00:03:00'),
      },
    ];

    afterAll(() => {
      const jsonPath = path.join(reportsDir, `${scanId}.json`);
      if (fs.existsSync(jsonPath)) fs.unlinkSync(jsonPath);
    });

    it('generates JSON report file', async () => {
      await service.generate(scanId, scan, vulns, ['json']);
      const jsonPath = path.join(reportsDir, `${scanId}.json`);
      expect(fs.existsSync(jsonPath)).toBe(true);
      const report = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
      expect(report.meta.scanId).toBe(scanId);
      expect(report.meta.target).toBe('https://target.com');
      expect(report.summary.totalVulns).toBe(1);
      expect(report.summary.high).toBe(1);
      expect(report.vulnerabilities).toHaveLength(1);
      expect(report.vulnerabilities[0].payload).toBe('<script>alert(1)</script>');
    });
  });
});
