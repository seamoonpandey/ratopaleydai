import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { ScanService } from '../scan/scan.service';
import { ScanGateway } from '../scan/scan.gateway';
import { ContextClientService } from '../modules-bridge/context-client.service';
import { PayloadClientService } from '../modules-bridge/payload-client.service';
import { FuzzerClientService } from '../modules-bridge/fuzzer-client.service';
import { ReportService } from '../report/report.service';
import { ScanStatus, ScanPhase } from '../common/interfaces/scan.interface';
import { SCAN_QUEUE } from './scan.producer';

@Processor(SCAN_QUEUE)
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    private readonly scanService: ScanService,
    private readonly gateway: ScanGateway,
    private readonly contextClient: ContextClientService,
    private readonly payloadClient: PayloadClientService,
    private readonly fuzzerClient: FuzzerClientService,
    private readonly reportService: ReportService,
  ) {
    super();
  }

  async process(job: Job<{ scanId: string }>): Promise<void> {
    const { scanId } = job.data;
    const scan = this.scanService.findOne(scanId);
    const startedAt = Date.now();

    try {
      // ── Phase 1: CRAWL ──────────────────────────────────────────────
      this.scanService.updateStatus(scanId, ScanStatus.CRAWLING, ScanPhase.CRAWL, 5);
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 5,
        message: 'crawling target, discovering params',
      });

      // placeholder — real crawler service wired in Day 7
      const discoveredParams = ['q', 'search', 'id'];
      const waf = 'none';

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 20,
        message: `found ${discoveredParams.length} params`,
      });

      // ── Phase 2: CONTEXT ────────────────────────────────────────────
      this.scanService.updateStatus(scanId, ScanStatus.ANALYZING, ScanPhase.CONTEXT, 25);
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CONTEXT,
        progress: 25,
        message: 'analyzing reflection contexts via AI',
      });

      const contexts = await this.contextClient.analyze({
        url: scan.url,
        params: discoveredParams,
        waf,
      });

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CONTEXT,
        progress: 40,
        message: 'context analysis complete',
      });

      // ── Phase 3: PAYLOAD-GEN ────────────────────────────────────────
      this.scanService.updateStatus(scanId, ScanStatus.GENERATING, ScanPhase.PAYLOAD_GEN, 45);
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.PAYLOAD_GEN,
        progress: 45,
        message: 'generating ranked payloads',
      });

      const { payloads } = await this.payloadClient.generate({
        contexts,
        waf,
        maxPayloads: scan.options.maxPayloadsPerParam ?? 50,
      });

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.PAYLOAD_GEN,
        progress: 60,
        message: `${payloads.length} payloads generated`,
      });

      // ── Phase 4: FUZZ ───────────────────────────────────────────────
      this.scanService.updateStatus(scanId, ScanStatus.FUZZING, ScanPhase.FUZZ, 65);
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.FUZZ,
        progress: 65,
        message: 'fuzzing target with payloads',
      });

      const { results } = await this.fuzzerClient.test({
        url: scan.url,
        payloads,
        verifyExecution: scan.options.verifyExecution ?? true,
        timeout: scan.options.timeout ?? 60000,
      });

      const confirmedVulns = results.filter((r) => r.vuln);
      for (const r of confirmedVulns) {
        const vuln = this.reportService.buildVuln(scanId, scan.url, r);
        this.scanService.addVuln(scanId, vuln);
        this.gateway.emitFinding({ scanId, vuln });
      }

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.FUZZ,
        progress: 85,
        message: `${confirmedVulns.length} vulnerabilities confirmed`,
      });

      // ── Phase 5: REPORT ─────────────────────────────────────────────
      this.scanService.updateStatus(scanId, ScanStatus.REPORTING, ScanPhase.REPORT, 90);
      const vulns = this.scanService.getVulns(scanId);
      const reportUrl = await this.reportService.generate(
        scanId,
        scan,
        vulns,
        scan.options.reportFormat ?? ['html', 'json'],
      );

      this.scanService.updateStatus(scanId, ScanStatus.DONE, ScanPhase.REPORT, 100);

      const durationMs = Date.now() - startedAt;
      this.gateway.emitComplete({
        scanId,
        summary: {
          totalParams: discoveredParams.length,
          paramsTested: discoveredParams.length,
          vulnsFound: vulns.length,
          durationMs,
        },
        reportUrl,
      });

      this.logger.log(
        `scan complete scanId=${scanId} vulns=${vulns.length} ms=${durationMs}`,
      );
    } catch (err: any) {
      const msg: string = err?.message ?? 'unknown error';
      this.logger.error(`scan failed scanId=${scanId} error=${msg}`);
      this.scanService.markFailed(scanId, msg);
      this.gateway.emitError(scanId, msg);
      throw err; // let BullMQ retry
    }
  }
}
