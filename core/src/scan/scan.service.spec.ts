import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanService } from './scan.service';
import { ScanEntity } from './entities/scan.entity';
import { VulnEntity } from './entities/vuln.entity';
import { ScanStatus, ScanPhase } from '../common/interfaces/scan.interface';
import {
  ScanNotFoundException,
  ScanAlreadyRunningException,
  ScanCancelException,
} from '../common/exceptions/scan.exceptions';

describe('ScanService', () => {
  let service: ScanService;
  let module: TestingModule;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'better-sqlite3',
          database: ':memory:',
          entities: [ScanEntity, VulnEntity],
          synchronize: true,
        }),
        TypeOrmModule.forFeature([ScanEntity, VulnEntity]),
      ],
      providers: [ScanService],
    }).compile();
  });

  beforeEach(async () => {
    service = module.get(ScanService);
    await service.deleteAllScans();
  });

  afterAll(async () => {
    await module.close();
  });

  describe('create', () => {
    it('creates a scan with default options', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      expect(scan.id).toBeDefined();
      expect(scan.url).toBe('https://example.com');
      expect(scan.status).toBe(ScanStatus.PENDING);
      expect(scan.progress).toBe(0);
      expect(scan.options.depth).toBe(3);
      expect(scan.options.maxPayloadsPerParam).toBe(50);
      expect(scan.options.verifyExecution).toBe(true);
      expect(scan.options.wafBypass).toBe(true);
      expect(scan.createdAt).toBeInstanceOf(Date);
    });

    it('normalizes url by stripping trailing slash', async () => {
      const scan = await service.create({ url: 'https://example.com/' });
      expect(scan.url).toBe('https://example.com');
    });

    it('respects custom options', async () => {
      const scan = await service.create({
        url: 'https://example.com',
        options: { depth: 5, maxPayloadsPerParam: 100 },
      });
      expect(scan.options.depth).toBe(5);
      expect(scan.options.maxPayloadsPerParam).toBe(100);
    });

    it('initializes empty vuln list', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const vulns = await service.getVulns(scan.id);
      expect(vulns).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('returns existing scan', async () => {
      const created = await service.create({ url: 'https://example.com' });
      const found = await service.findOne(created.id);
      expect(found.id).toBe(created.id);
    });

    it('throws ScanNotFoundException for unknown id', async () => {
      await expect(service.findOne('nonexistent')).rejects.toThrow(
        ScanNotFoundException,
      );
    });
  });

  describe('findAll', () => {
    it('returns empty array when no scans exist', async () => {
      const all = await service.findAll();
      expect(all).toEqual([]);
    });

    it('returns scans sorted by createdAt descending', async () => {
      await service.create({ url: 'https://a.com' });
      await new Promise((r) => setTimeout(r, 50));
      const s2 = await service.create({ url: 'https://b.com' });
      const all = await service.findAll();
      expect(all.length).toBe(2);
      expect(all[0].id).toBe(s2.id);
    });
  });

  describe('getVulns', () => {
    it('throws for unknown scan id', async () => {
      await expect(service.getVulns('nonexistent')).rejects.toThrow(
        ScanNotFoundException,
      );
    });

    it('returns added vulns', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const vuln = {
        id: 'v1',
        scanId: scan.id,
        url: 'https://example.com',
        param: 'q',
        payload: '<script>alert(1)</script>',
        type: 'REFLECTED_XSS' as any,
        severity: 'HIGH' as any,
        reflected: true,
        executed: true,
        evidence: {
          responseCode: 200,
          reflectionPosition: 'body',
          browserAlertTriggered: true,
        },
        discoveredAt: new Date(),
      };
      expect(await service.addVuln(scan.id, vuln)).toBe(true);
      const vulns = await service.getVulns(scan.id);
      expect(vulns).toHaveLength(1);
      expect(vulns[0].param).toBe('q');
    });

    it('dedupes identical vulns', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const vuln = {
        id: 'v1',
        scanId: scan.id,
        url: 'https://example.com/search?q=',
        param: 'q',
        payload: '<script>alert(1)</script>',
        type: 'REFLECTED_XSS' as any,
        severity: 'HIGH' as any,
        reflected: true,
        executed: true,
        evidence: {
          responseCode: 200,
          reflectionPosition: 'body',
          browserAlertTriggered: true,
        },
        discoveredAt: new Date(),
      };

      expect(await service.addVuln(scan.id, vuln)).toBe(true);
      expect(await service.addVuln(scan.id, { ...vuln, id: 'v2' })).toBe(false);
      expect(await service.getVulns(scan.id)).toHaveLength(1);
    });

    it('dedupes reflected xss across different payload variants', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const base = {
        scanId: scan.id,
        url: 'https://example.com/search?q=hello',
        param: 'q',
        type: 'reflected_xss' as any,
        severity: 'MEDIUM' as any,
        reflected: true,
        executed: false,
        evidence: {
          responseCode: 200,
          reflectionPosition: 'body',
          browserAlertTriggered: false,
        },
        discoveredAt: new Date(),
      };

      expect(
        await service.addVuln(scan.id, {
          ...base,
          id: 'v1',
          payload: '"/><img src=x onerror=alert(1)>',
        } as any),
      ).toBe(true);

      expect(
        await service.addVuln(scan.id, {
          ...base,
          id: 'v2',
          payload: '<svg onload=alert(1)>',
        } as any),
      ).toBe(false);

      expect(await service.getVulns(scan.id)).toHaveLength(1);
    });
  });

  describe('cancel', () => {
    it('cancels a pending scan', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const cancelled = await service.cancel(scan.id);
      expect(cancelled.status).toBe(ScanStatus.CANCELLED);
      expect(cancelled.completedAt).toBeInstanceOf(Date);
    });

    it('cancels a crawling scan', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      await service.updateStatus(scan.id, ScanStatus.CRAWLING, ScanPhase.CRAWL, 10);
      const cancelled = await service.cancel(scan.id);
      expect(cancelled.status).toBe(ScanStatus.CANCELLED);
    });

    it('throws ScanCancelException for a completed scan', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      await service.updateStatus(scan.id, ScanStatus.DONE);
      await expect(service.cancel(scan.id)).rejects.toThrow(ScanCancelException);
    });

    it('throws ScanCancelException for a failed scan', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      await service.markFailed(scan.id, 'some error');
      await expect(service.cancel(scan.id)).rejects.toThrow(ScanCancelException);
    });
  });

  describe('updateStatus', () => {
    it('updates status, phase, and progress', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const updated = await service.updateStatus(
        scan.id,
        ScanStatus.CRAWLING,
        ScanPhase.CRAWL,
        25,
      );
      expect(updated.status).toBe(ScanStatus.CRAWLING);
      expect(updated.phase).toBe(ScanPhase.CRAWL);
      expect(updated.progress).toBe(25);
    });

    it('throws ScanAlreadyRunningException when starting already running scan', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      await service.updateStatus(scan.id, ScanStatus.CRAWLING, ScanPhase.CRAWL, 10);
      await expect(
        service.updateStatus(scan.id, ScanStatus.CRAWLING),
      ).rejects.toThrow(ScanAlreadyRunningException);
    });

    it('sets completedAt for terminal statuses', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      expect(scan.completedAt).toBeUndefined();
      const done = await service.updateStatus(scan.id, ScanStatus.DONE);
      expect(done.completedAt).toBeInstanceOf(Date);
    });
  });

  describe('markFailed', () => {
    it('sets status to FAILED with error message', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      const failed = await service.markFailed(scan.id, 'timeout');
      expect(failed.status).toBe(ScanStatus.FAILED);
      expect(failed.error).toBe('timeout');
      expect(failed.completedAt).toBeInstanceOf(Date);
    });
  });

  describe('deleteScan', () => {
    it('removes scan and its vulns', async () => {
      const scan = await service.create({ url: 'https://example.com' });
      await service.addVuln(scan.id, {
        id: 'v1',
        scanId: scan.id,
        url: 'https://example.com',
        param: 'q',
        payload: '<script>alert(1)</script>',
        type: 'reflected_xss' as any,
        severity: 'HIGH' as any,
        reflected: true,
        executed: true,
        evidence: {
          responseCode: 200,
          reflectionPosition: 'body',
          browserAlertTriggered: true,
        },
        discoveredAt: new Date(),
      });

      await service.deleteScan(scan.id);
      await expect(service.findOne(scan.id)).rejects.toThrow(ScanNotFoundException);
    });

    it('throws for unknown scan id', async () => {
      await expect(service.deleteScan('nonexistent')).rejects.toThrow(
        ScanNotFoundException,
      );
    });
  });

  describe('deleteAllScans', () => {
    it('removes all scans', async () => {
      await service.create({ url: 'https://a.com' });
      await service.create({ url: 'https://b.com' });
      const count = await service.deleteAllScans();
      expect(count).toBe(2);
      const all = await service.findAll();
      expect(all).toHaveLength(0);
    });
  });
});
