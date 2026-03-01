import { Injectable, Logger } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { CreateScanDto } from './dto/create-scan.dto';
import {
  ScanRecord,
  ScanStatus,
  ScanPhase,
} from '../common/interfaces/scan.interface';
import { Vuln } from '../common/interfaces/vuln.interface';
import {
  ScanNotFoundException,
  ScanAlreadyRunningException,
  ScanCancelException,
} from '../common/exceptions/scan.exceptions';
import { normalizeUrl } from '../common/utils/url.utils';

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);
  private readonly scans = new Map<string, ScanRecord>();
  private readonly vulns = new Map<string, Vuln[]>();

  create(dto: CreateScanDto): ScanRecord {
    const id = uuidv4();
    const now = new Date();
    const record: ScanRecord = {
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
    };
    this.scans.set(id, record);
    this.vulns.set(id, []);
    this.logger.log(`scan created id=${id} url=${record.url}`);
    return record;
  }

  findOne(id: string): ScanRecord {
    const scan = this.scans.get(id);
    if (!scan) throw new ScanNotFoundException(id);
    return scan;
  }

  findAll(): ScanRecord[] {
    return Array.from(this.scans.values()).sort(
      (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
    );
  }

  getVulns(id: string): Vuln[] {
    this.findOne(id); // throws if not found
    return this.vulns.get(id) ?? [];
  }

  cancel(id: string): ScanRecord {
    const scan = this.findOne(id);
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

  updateStatus(
    id: string,
    status: ScanStatus,
    phase?: ScanPhase,
    progress?: number,
  ): ScanRecord {
    const scan = this.findOne(id);
    if (status === ScanStatus.CRAWLING && !this.isIdle(scan)) {
      throw new ScanAlreadyRunningException(id);
    }
    scan.status = status;
    scan.updatedAt = new Date();
    if (phase !== undefined) scan.phase = phase;
    if (progress !== undefined) scan.progress = progress;
    if (
      status === ScanStatus.DONE ||
      status === ScanStatus.FAILED ||
      status === ScanStatus.CANCELLED
    ) {
      scan.completedAt = new Date();
    }
    return scan;
  }

  addVuln(scanId: string, vuln: Vuln): void {
    this.findOne(scanId);
    const list = this.vulns.get(scanId) ?? [];
    list.push(vuln);
    this.vulns.set(scanId, list);
  }

  markFailed(id: string, error: string): ScanRecord {
    const scan = this.findOne(id);
    scan.status = ScanStatus.FAILED;
    scan.error = error;
    scan.updatedAt = new Date();
    scan.completedAt = new Date();
    return scan;
  }

  private isIdle(scan: ScanRecord): boolean {
    return scan.status === ScanStatus.PENDING;
  }
}
