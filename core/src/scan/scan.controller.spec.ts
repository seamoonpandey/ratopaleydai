import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScanController } from './scan.controller';
import { ScanService } from './scan.service';
import { ScanEntity } from './entities/scan.entity';
import { VulnEntity } from './entities/vuln.entity';
import { ScanQueueProducer } from '../queue/scan.producer';
import { ApiKeyGuard } from '../auth/api-key.guard';
import { ScanStatus } from '../common/interfaces/scan.interface';

describe('ScanController', () => {
  let controller: ScanController;
  let scanService: ScanService;
  let queueProducer: ScanQueueProducer;
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
      controllers: [ScanController],
      providers: [
        ScanService,
        {
          provide: ScanQueueProducer,
          useValue: { enqueue: jest.fn().mockResolvedValue(undefined) },
        },
      ],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(ScanController);
    scanService = module.get(ScanService);
    queueProducer = module.get(ScanQueueProducer);
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    await scanService.deleteAllScans();
  });

  afterAll(async () => {
    await module.close();
  });

  describe('createScan', () => {
    it('creates a scan and enqueues it', async () => {
      const result = await controller.createScan({
        url: 'https://example.com',
      });
      expect(result).toBeDefined();
      expect(result.url).toBe('https://example.com');
      expect(queueProducer.enqueue).toHaveBeenCalledWith(result.id);
    });
  });

  describe('getScan', () => {
    it('returns scan with vulns', async () => {
      const scan = await scanService.create({ url: 'https://example.com' });
      const result = await controller.getScan(scan.id);
      expect(result.id).toBe(scan.id);
      expect(result.vulns).toEqual([]);
    });
  });

  describe('cancelScan', () => {
    it('cancels a pending scan', async () => {
      const scan = await scanService.create({ url: 'https://example.com' });
      await expect(controller.cancelScan(scan.id)).resolves.not.toThrow();
      const check = await scanService.findOne(scan.id);
      expect(check.status).toBe(ScanStatus.CANCELLED);
    });
  });

  describe('listScans', () => {
    it('returns paginated list', async () => {
      for (let i = 0; i < 5; i++) {
        await scanService.create({ url: `https://${i}.com` });
      }
      const page1 = await controller.listScans(1, 2);
      expect(page1).toHaveLength(2);

      const page3 = await controller.listScans(3, 2);
      expect(page3).toHaveLength(1);
    });

    it('returns empty for out-of-range page', async () => {
      await scanService.create({ url: 'https://example.com' });
      const result = await controller.listScans(100, 20);
      expect(result).toHaveLength(0);
    });
  });

  describe('getReport', () => {
    it('returns report url for existing scan', async () => {
      const scan = await scanService.create({ url: 'https://example.com' });
      const result = await controller.getReport(scan.id);
      expect(result.reportUrl).toContain(scan.id);
    });
  });

  describe('deleteScan', () => {
    it('deletes a scan permanently', async () => {
      const scan = await scanService.create({ url: 'https://example.com' });
      await controller.deleteScan(scan.id);
      await expect(scanService.findOne(scan.id)).rejects.toThrow();
    });
  });

  describe('deleteAllScans', () => {
    it('clears all scans', async () => {
      await scanService.create({ url: 'https://a.com' });
      await scanService.create({ url: 'https://b.com' });
      const result = await controller.deleteAllScans();
      expect(result.deleted).toBe(2);
    });
  });

  describe('health', () => {
    it('returns ok status', () => {
      const result = controller.health();
      expect(result.status).toBe('ok');
      expect(result.timestamp).toBeDefined();
    });
  });
});
