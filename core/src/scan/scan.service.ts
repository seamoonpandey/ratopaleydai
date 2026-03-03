import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { randomUUID as uuidv4 } from 'crypto';
import { CreateScanDto } from './dto/create-scan.dto';
import {
  ScanRecord,
  ScanStatus,
  ScanPhase,
} from '../common/interfaces/scan.interface';
import { Vuln, VulnType } from '../common/interfaces/vuln.interface';
import {
  ScanNotFoundException,
  ScanAlreadyRunningException,
  ScanCancelException,
} from '../common/exceptions/scan.exceptions';
import { normalizeUrl } from '../common/utils/url.utils';
import { ScanEntity } from './entities/scan.entity';
import { VulnEntity } from './entities/vuln.entity';

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);

  /**
   * In-memory dedup sets survive only for the lifetime of the process.
   * This is fine — dedup only matters during a single scan run; if the
   * process restarts mid-scan, BullMQ will re-queue the job anyway.
   */
  private readonly vulnKeys = new Map<string, Set<string>>();

  constructor(
    @InjectRepository(ScanEntity)
    private readonly scanRepo: Repository<ScanEntity>,
    @InjectRepository(VulnEntity)
    private readonly vulnRepo: Repository<VulnEntity>,
  ) {}

  async create(dto: CreateScanDto): Promise<ScanRecord> {
    const id = uuidv4();
    const now = new Date();
    const entity = this.scanRepo.create({
      id,
      url: normalizeUrl(dto.url),
      status: ScanStatus.PENDING,
      progress: 0,
      options: {
        depth: dto.options?.depth ?? 3,
        maxParams: dto.options?.maxParams ?? 100,
        verifyExecution: dto.options?.verifyExecution ?? true,
        wafBypass: dto.options?.wafBypass ?? true,
        maxPayloadsPerParam: dto.options?.maxPayloadsPerParam ?? 50,
        timeout: dto.options?.timeout ?? 60000,
        reportFormat: dto.options?.reportFormat ?? ['html', 'json'],
      },
      createdAt: now,
      updatedAt: now,
    });
    const saved = await this.scanRepo.save(entity);
    this.vulnKeys.set(id, new Set());
    this.logger.log(`scan created id=${id} url=${saved.url}`);
    return this.toRecord(saved);
  }

  async findOne(id: string): Promise<ScanRecord> {
    const scan = await this.scanRepo.findOneBy({ id });
    if (!scan) throw new ScanNotFoundException(id);
    return this.toRecord(scan);
  }

  async findAll(): Promise<ScanRecord[]> {
    const scans = await this.scanRepo.find({
      order: { createdAt: 'DESC' },
    });
    return scans.map((s) => this.toRecord(s));
  }

  async getVulns(id: string): Promise<Vuln[]> {
    await this.findOne(id); // throws if not found
    const entities = await this.vulnRepo.find({
      where: { scanId: id },
      order: { discoveredAt: 'ASC' },
    });
    return entities.map((e) => this.toVuln(e));
  }

  async cancel(id: string): Promise<ScanRecord> {
    const scan = await this.findOne(id);
    const cancellable: ScanStatus[] = [
      ScanStatus.PENDING,
      ScanStatus.CRAWLING,
      ScanStatus.ANALYZING,
      ScanStatus.GENERATING,
      ScanStatus.FUZZING,
    ];
    if (!cancellable.includes(scan.status)) {
      throw new ScanCancelException(id);
    }
    return this.updateStatus(id, ScanStatus.CANCELLED);
  }

  async updateStatus(
    id: string,
    status: ScanStatus,
    phase?: ScanPhase,
    progress?: number,
  ): Promise<ScanRecord> {
    const scan = await this.findOne(id);
    if (status === ScanStatus.CRAWLING && !this.isIdle(scan)) {
      throw new ScanAlreadyRunningException(id);
    }

    const updates: Partial<ScanEntity> = {
      status,
      updatedAt: new Date(),
    };
    if (phase !== undefined) updates.phase = phase;
    if (progress !== undefined) updates.progress = progress;
    if (
      status === ScanStatus.DONE ||
      status === ScanStatus.FAILED ||
      status === ScanStatus.CANCELLED
    ) {
      updates.completedAt = new Date();
    }

    await this.scanRepo.update(id, updates);
    return this.findOne(id);
  }

  async addVuln(scanId: string, vuln: Vuln): Promise<boolean> {
    await this.findOne(scanId);
    const key = this.buildVulnKey(vuln);
    const seen = this.vulnKeys.get(scanId) ?? new Set<string>();
    if (seen.has(key)) return false;
    seen.add(key);
    this.vulnKeys.set(scanId, seen);

    const entity = this.vulnRepo.create({
      id: vuln.id ?? uuidv4(),
      scanId,
      url: vuln.url,
      param: vuln.param,
      payload: vuln.payload,
      type: vuln.type,
      severity: vuln.severity,
      reflected: vuln.reflected,
      executed: vuln.executed,
      evidence: vuln.evidence,
      discoveredAt: vuln.discoveredAt ?? new Date(),
    });
    await this.vulnRepo.save(entity);
    return true;
  }

  async markFailed(id: string, error: string): Promise<ScanRecord> {
    await this.scanRepo.update(id, {
      status: ScanStatus.FAILED,
      error,
      updatedAt: new Date(),
      completedAt: new Date(),
    });
    return this.findOne(id);
  }

  // ── delete / clear operations ────────────────────────────────

  async deleteScan(id: string): Promise<void> {
    const scan = await this.scanRepo.findOneBy({ id });
    if (!scan) throw new ScanNotFoundException(id);
    // CASCADE delete removes vulns automatically
    await this.scanRepo.remove(scan);
    this.vulnKeys.delete(id);
    this.logger.log(`scan deleted id=${id}`);
  }

  async deleteAllScans(): Promise<number> {
    const count = await this.scanRepo.count();
    await this.vulnRepo.clear();
    await this.scanRepo.clear();
    this.vulnKeys.clear();
    this.logger.warn(`all scans deleted (${count} scans removed)`);
    return count;
  }

  // ── private helpers ──────────────────────────────────────────

  private toRecord(e: ScanEntity): ScanRecord {
    return {
      id: e.id,
      url: e.url,
      status: e.status,
      phase: e.phase,
      progress: e.progress,
      options: e.options,
      createdAt: e.createdAt,
      updatedAt: e.updatedAt,
      completedAt: e.completedAt ?? undefined,
      error: e.error ?? undefined,
    };
  }

  private toVuln(e: VulnEntity): Vuln {
    return {
      id: e.id,
      scanId: e.scanId,
      url: e.url,
      param: e.param,
      payload: e.payload,
      type: e.type,
      severity: e.severity,
      reflected: e.reflected,
      executed: e.executed,
      evidence: e.evidence,
      discoveredAt: e.discoveredAt,
    };
  }

  private buildVulnKey(v: Vuln): string {
    const type = String(v.type ?? '').trim();
    const url = this.normalizeUrlForDedup(String(v.url ?? '').trim());
    const param = String(v.param ?? '').trim();
    const payload = String(v.payload ?? '').trim();

    if (type === VulnType.REFLECTED_XSS || type === VulnType.STORED_XSS) {
      return `${type}|${url}|${param}`;
    }

    if (type === VulnType.DOM_XSS) {
      return `${type}|${url}|${payload}`;
    }

    return `${type}|${url}|${param}|${payload}`;
  }

  private normalizeUrlForDedup(rawUrl: string): string {
    try {
      const u = new URL(rawUrl);
      const keys = [...new Set([...u.searchParams.keys()])].sort();
      const qs =
        keys.length > 0
          ? `?${keys.map((k) => `${encodeURIComponent(k)}=`).join('&')}`
          : '';
      return `${u.origin}${u.pathname}${qs}`;
    } catch {
      return rawUrl;
    }
  }

  private isIdle(scan: ScanRecord): boolean {
    return scan.status === ScanStatus.PENDING;
  }
}
