import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { ScanService } from '../scan/scan.service';
import { ScanGateway } from '../scan/scan.gateway';
import { CrawlerService } from '../crawler/crawler.service';
import { ContextClientService } from '../modules-bridge/context-client.service';
import { PayloadClientService } from '../modules-bridge/payload-client.service';
import { FuzzerClientService } from '../modules-bridge/fuzzer-client.service';
import { ReportService } from '../report/report.service';
import {
  ScanStatus,
  ScanPhase,
  ScanRecord,
} from '../common/interfaces/scan.interface';
import { SCAN_QUEUE } from './scan.producer';

const SCAN_WORKER_CONCURRENCY = Math.max(
  1,
  Number(process.env.SCAN_WORKER_CONCURRENCY ?? 2),
);

function canonicalizeTargetUrl(
  rawUrl: string,
  baseUrl?: string,
): { url: string; params: string[] } {
  try {
    const u = baseUrl ? new URL(rawUrl, baseUrl) : new URL(rawUrl);
    const paramNames = [...new Set([...u.searchParams.keys()])].sort();
    const canonicalSearch =
      paramNames.length > 0
        ? `?${paramNames.map((p) => `${encodeURIComponent(p)}=`).join('&')}`
        : '';
    const canonicalUrl = `${u.origin}${u.pathname}${canonicalSearch}`;
    return { url: canonicalUrl, params: paramNames };
  } catch {
    return { url: rawUrl, params: [] };
  }
}

@Processor(SCAN_QUEUE, { concurrency: SCAN_WORKER_CONCURRENCY })
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    private readonly scanService: ScanService,
    private readonly gateway: ScanGateway,
    private readonly crawlerService: CrawlerService,
    private readonly contextClient: ContextClientService,
    private readonly payloadClient: PayloadClientService,
    private readonly fuzzerClient: FuzzerClientService,
    private readonly reportService: ReportService,
  ) {
    super();
  }

  /** Extract a numeric post/article ID from a URL query string */
  private extractPostId(url: string): string | null {
    try {
      const u = new URL(url);
      for (const key of ['postId', 'post_id', 'id', 'articleId', 'article_id']) {
        const val = u.searchParams.get(key);
        if (val) return val;
      }
    } catch { /* ignore */ }
    return null;
  }

  async process(job: Job<{ scanId: string }>): Promise<void> {
    const { scanId } = job.data;
    const startedAt = Date.now();

    try {
      let scan: ScanRecord;
      try {
        scan = this.scanService.findOne(scanId);
      } catch (err) {
        const detail = err instanceof Error ? err.message : 'scan not found';
        this.logger.warn(
          `skipping scan job for missing scanId=${scanId}: ${detail}`,
        );
        return;
      }

      // ── Phase 1: CRAWL ──────────────────────────────────────────────
      this.scanService.updateStatus(
        scanId,
        ScanStatus.CRAWLING,
        ScanPhase.CRAWL,
        5,
      );
      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 5,
        message: scan.options.singlePage
          ? 'single-page mode — skipping crawl'
          : 'crawling target, discovering params',
      });

      const urlParamsMap = new Map<string, string[]>();
      let waf = 'none';
      let crawledForms: import('../common/interfaces/crawler.interface').DiscoveredForm[] = [];

      if (scan.options.singlePage) {
        // ── Single-page fast path: just parse the given URL ──────────
        const { url: canonicalRoot, params: rootParams } =
          canonicalizeTargetUrl(scan.url);
        urlParamsMap.set(canonicalRoot, rootParams);
      } else {
        // ── Crawl the target site ─────────────────────────────────────
        const crawlResult = await this.crawlerService.crawl(
          scan.url,
          scan.options.depth ?? 3,
          scan.options.maxParams ?? 100,
        );

        waf = crawlResult.waf.name ?? 'none';
        crawledForms = crawlResult.forms;

        // The crawler returns individual URLs it visited; extract query
        // params from each so context/fuzz target the actual page.
        for (const crawledUrl of crawlResult.urls) {
          const { url: canonicalUrl, params } = canonicalizeTargetUrl(crawledUrl);
          const existing = urlParamsMap.get(canonicalUrl) ?? [];
          urlParamsMap.set(canonicalUrl, [...new Set([...existing, ...params])]);
        }

        // Also include form action URLs with their fields
        for (const form of crawlResult.forms) {
          if (form.action && form.fields.length > 0) {
            const { url: canonicalUrl, params } = canonicalizeTargetUrl(
              form.action,
              scan.url,
            );
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, ...params, ...form.fields]),
            ]);
          }
        }

        // Include params discovered from HTML forms (e.g. search bars)
        // that aren't already captured via URL query strings or form actions
        for (const param of crawlResult.params) {
          if (param.source === 'form' && param.formAction) {
            const { url: canonicalUrl, params: existingUrlParams } =
              canonicalizeTargetUrl(param.formAction, scan.url);
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, ...existingUrlParams, param.name]),
            ]);
          } else if (param.source === 'form' && !param.formAction) {
            // form with no explicit action targets the page it's on;
            // associate with the base scan URL
            const { url: canonicalUrl } = canonicalizeTargetUrl(scan.url);
            const existing = urlParamsMap.get(canonicalUrl) ?? [];
            urlParamsMap.set(canonicalUrl, [
              ...new Set([...existing, param.name]),
            ]);
          }
        }

        // Ensure the original scan URL is included if it has params
        try {
          const { url: canonicalRoot, params: rootParams } =
            canonicalizeTargetUrl(scan.url);
          if (rootParams.length > 0 && !urlParamsMap.has(canonicalRoot)) {
            urlParamsMap.set(canonicalRoot, rootParams);
          }
        } catch {
          // skip
        }
      }

      const targetEntries = Array.from(urlParamsMap.entries());
      const totalUniqueParams = new Set(
        targetEntries.flatMap(([, params]) => params),
      ).size;

      this.gateway.emitProgress({
        scanId,
        phase: ScanPhase.CRAWL,
        progress: 20,
        message: `found ${totalUniqueParams} params across ${targetEntries.length} url(s)${
          waf !== 'none' ? `, waf: ${waf}` : ''
        }`,
      });

      if (targetEntries.length === 0) {
        this.logger.warn(
          `no parameterized URLs found for scanId=${scanId}, nothing to test`,
        );
        this.scanService.updateStatus(
          scanId,
          ScanStatus.DONE,
          ScanPhase.REPORT,
          100,
        );
        this.gateway.emitComplete({
          scanId,
          summary: {
            totalParams: 0,
            paramsTested: 0,
            vulnsFound: 0,
            durationMs: Date.now() - startedAt,
          },
          reportUrl: '',
        });
        return;
      }

      // ── Per-URL pipeline: CONTEXT → PAYLOAD-GEN → FUZZ ─────────────
      this.scanService.updateStatus(
        scanId,
        ScanStatus.ANALYZING,
        ScanPhase.CONTEXT,
        25,
      );

      let totalPayloadsTested = 0;
      let totalVulnsFound = 0;
      const totalTargets = targetEntries.length;

      for (let i = 0; i < totalTargets; i++) {
        const [targetUrl, targetParams] = targetEntries[i];
        const pct = (n: number) =>
          Math.round(25 + ((i + n) / totalTargets) * 60);

        this.logger.log(
          `[${i + 1}/${totalTargets}] processing ${targetUrl} (${targetParams.length} params)`,
        );

        // If this URL has no params at all, skip context/payload generation and
        // do a DOM-only scan (fetch + inline script analysis).
        if (targetParams.length === 0) {
          this.scanService.updateStatus(
            scanId,
            ScanStatus.FUZZING,
            ScanPhase.FUZZ,
            pct(0.5),
          );
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(0.5),
            message: `[${i + 1}/${totalTargets}] dom-only scanning ${targetUrl}`,
          });

          try {
            const domResp = await this.fuzzerClient.test({
              url: targetUrl,
              payloads: [],
              verifyExecution: false,
              timeout: scan.options.timeout ?? 60000,
            });
            const domVulns = domResp.results.filter((r) => r.vuln);
            for (const r of domVulns) {
              const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
              if (this.scanService.addVuln(scanId, vuln)) {
                this.gateway.emitFinding({ scanId, vuln });
              }
            }
            totalVulnsFound += domVulns.length;
          } catch (err) {
            const detail =
              err instanceof Error ? err.message : 'fuzzer error';
            this.logger.warn(
              `dom-only scan failed for ${targetUrl}: ${detail}, skipping`,
            );
          }

          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(1),
            message: `[${i + 1}/${totalTargets}] dom-only done (${totalVulnsFound} total)`,
          });
          continue;
        }

        // ── CONTEXT for this URL ────────────────────────────────────
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.CONTEXT,
          progress: pct(0),
          message: `[${i + 1}/${totalTargets}] analyzing ${targetUrl}`,
        });

        let contexts;
        try {
          contexts = await this.contextClient.analyze({
            url: targetUrl,
            params: targetParams,
            waf,
          });
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'context module error';
          this.logger.warn(
            `context failed for ${targetUrl}: ${detail}, skipping`,
          );
          continue;
        }

        // skip if no reflections found for this URL
        const reflectedParams = Object.entries(contexts).filter(
          ([, ctx]) =>
            (ctx as { reflects_in: string }).reflects_in !== 'none',
        );
        if (reflectedParams.length === 0) {
          this.logger.debug(
            `no reflections on ${targetUrl}, running dom-only scan`,
          );

          this.scanService.updateStatus(
            scanId,
            ScanStatus.FUZZING,
            ScanPhase.FUZZ,
            pct(0.5),
          );
          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(0.5),
            message: `[${i + 1}/${totalTargets}] dom-only scanning ${targetUrl}`,
          });

          try {
            const domResp = await this.fuzzerClient.test({
              url: targetUrl,
              payloads: [],
              verifyExecution: false,
              timeout: scan.options.timeout ?? 60000,
            });
            const domVulns = domResp.results.filter((r) => r.vuln);
            for (const r of domVulns) {
              const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
              if (this.scanService.addVuln(scanId, vuln)) {
                this.gateway.emitFinding({ scanId, vuln });
              }
            }
            totalVulnsFound += domVulns.length;
          } catch (err) {
            const detail =
              err instanceof Error ? err.message : 'fuzzer error';
            this.logger.warn(
              `dom-only scan failed for ${targetUrl}: ${detail}, skipping`,
            );
          }

          this.gateway.emitProgress({
            scanId,
            phase: ScanPhase.FUZZ,
            progress: pct(1),
            message: `[${i + 1}/${totalTargets}] dom-only done (${totalVulnsFound} total)`,
          });
          continue;
        }

        this.logger.log(
          `${reflectedParams.length} reflecting params on ${targetUrl}`,
        );

        // ── PAYLOAD-GEN for this URL ────────────────────────────────
        this.scanService.updateStatus(
          scanId,
          ScanStatus.GENERATING,
          ScanPhase.PAYLOAD_GEN,
          pct(0.33),
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.PAYLOAD_GEN,
          progress: pct(0.33),
          message: `[${i + 1}/${totalTargets}] generating payloads for ${targetUrl}`,
        });

        let payloads;
        try {
          const genResp = await this.payloadClient.generate({
            contexts,
            waf,
            maxPayloads: scan.options.maxPayloadsPerParam ?? 50,
          });
          payloads = genResp.payloads;
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'payload-gen error';
          this.logger.warn(
            `payload-gen failed for ${targetUrl}: ${detail}, skipping`,
          );
          continue;
        }

        if (payloads.length === 0) {
          this.logger.debug(`no payloads generated for ${targetUrl}`);
          continue;
        }

        // ── Deduplicate payloads before fuzzing ─────────────────────
        // Group by target_param and keep at most maxPayloadsPerParam
        // unique payloads per param. This prevents the fuzzer from sending
        // redundant HTTP requests for identical payloads or the same vuln.
        const maxPerParam = scan.options.maxPayloadsPerParam ?? 10;
        const perParam = new Map<string, Set<string>>();
        const uniquePayloads: typeof payloads = [];
        for (const p of payloads) {
          const paramKey = String(p.target_param ?? '');
          if (!perParam.has(paramKey)) perParam.set(paramKey, new Set());
          const seen = perParam.get(paramKey)!;
          if (seen.has(p.payload)) continue; // exact duplicate
          if (seen.size >= maxPerParam) continue; // per-param cap reached
          seen.add(p.payload);
          uniquePayloads.push(p);
        }
        if (uniquePayloads.length < payloads.length) {
          this.logger.debug(
            `deduped payloads ${payloads.length} → ${uniquePayloads.length} for ${targetUrl}`,
          );
        }

        // ── FUZZ for this URL ───────────────────────────────────────
        this.scanService.updateStatus(
          scanId,
          ScanStatus.FUZZING,
          ScanPhase.FUZZ,
          pct(0.66),
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: pct(0.66),
          message: `[${i + 1}/${totalTargets}] fuzzing ${targetUrl} with ${uniquePayloads.length} payloads`,
        });

        let results;
        try {
          // Derive dominant context for training data collection
          const contextEntries = Object.values(contexts) as Array<{ reflects_in: string; allowed_chars?: string[] }>;
          const dominantContext = contextEntries.length > 0 ? contextEntries[0].reflects_in : undefined;
          const dominantAllowedChars = contextEntries.length > 0 ? contextEntries[0].allowed_chars : undefined;

          const fuzzResp = await this.fuzzerClient.test({
            url: targetUrl,
            payloads: uniquePayloads,
            verifyExecution: scan.options.verifyExecution ?? true,
            timeout: scan.options.timeout ?? 60000,
            context: dominantContext,
            waf,
            allowedChars: dominantAllowedChars,
          });
          results = fuzzResp.results;
        } catch (err) {
          const detail =
            err instanceof Error ? err.message : 'fuzzer error';
          this.logger.warn(
            `fuzzer failed for ${targetUrl}: ${detail}, skipping`,
          );
          continue;
        }

        totalPayloadsTested += uniquePayloads.length;
        const confirmedVulns = results.filter((r) => r.vuln);
        for (const r of confirmedVulns) {
          const vuln = this.reportService.buildVuln(scanId, targetUrl, r);
          if (this.scanService.addVuln(scanId, vuln)) {
            this.gateway.emitFinding({ scanId, vuln });
          }
        }
        totalVulnsFound += confirmedVulns.length;

        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: pct(1),
          message: `[${i + 1}/${totalTargets}] ${confirmedVulns.length} vulns on ${targetUrl} (${totalVulnsFound} total)`,
        });
      }

      // ── Stored XSS sub-pipeline ─────────────────────────────────────
      // POST forms where action ≠ sourceUrl are stored XSS candidates.
      // The payload is submitted via form POST and appears on the source
      // page (or a related display page).
      const SKIP_FIELDS = new Set([
        'csrf', '_csrf', 'token', '_token', 'captcha', '__RequestVerificationToken',
      ]);
      const storedForms = crawledForms.filter(
        (f) =>
          f.method === 'POST' &&
          f.sourceUrl &&
          f.fields.length > 0,
      );

      if (storedForms.length > 0) {
        this.logger.log(
          `found ${storedForms.length} stored XSS form candidate(s)`,
        );
        this.gateway.emitProgress({
          scanId,
          phase: ScanPhase.FUZZ,
          progress: 86,
          message: `testing ${storedForms.length} form(s) for stored XSS`,
        });

        for (const form of storedForms) {
          const actionUrl = new URL(form.action, scan.url).href;
          const displayUrl = form.sourceUrl!;
          const testableFields = form.fields.filter(
            (f) => !SKIP_FIELDS.has(f.toLowerCase()),
          );

          if (testableFields.length === 0) continue;

          this.logger.log(
            `stored XSS: action=${actionUrl} display=${displayUrl} ` +
            `testable=${testableFields.join(',')}`,
          );

          // Build default form field values
          const defaultFields: Record<string, string> = {};
          for (const field of form.fields) {
            if (SKIP_FIELDS.has(field.toLowerCase())) continue;
            // provide sensible defaults for common field names
            const fl = field.toLowerCase();
            if (fl.includes('email')) defaultFields[field] = 'test@test.com';
            else if (fl.includes('name')) defaultFields[field] = 'testuser';
            else if (fl.includes('website') || fl.includes('url') || fl.includes('homepage'))
              defaultFields[field] = 'http://test.com';
            else if (fl.includes('postid') || fl.includes('post_id'))
              defaultFields[field] = this.extractPostId(displayUrl) ?? '1';
            else defaultFields[field] = 'test input';
          }

          // Build a synthetic context map for each testable field (html_body)
          const storedContexts: Record<string, { reflects_in: string; allowed_chars: string[]; context_confidence: number }> = {};
          for (const field of testableFields) {
            storedContexts[field] = {
              reflects_in: 'html_body',
              allowed_chars: ['<', '>', '"', "'", '/', '(', ')', ';', '='],
              context_confidence: 0.7,
            };
          }

          // Generate payloads for html_body context
          let storedPayloads;
          try {
            const genResp = await this.payloadClient.generate({
              contexts: storedContexts,
              waf,
              maxPayloads: scan.options.maxPayloadsPerParam ?? 20,
            });
            storedPayloads = genResp.payloads;
          } catch (err) {
            const detail = err instanceof Error ? err.message : 'payload-gen error';
            this.logger.warn(`stored XSS payload-gen failed: ${detail}, skipping`);
            continue;
          }

          if (storedPayloads.length === 0) {
            this.logger.debug('no payloads generated for stored XSS form');
            continue;
          }

          // Deduplicate
          const maxPerParam = scan.options.maxPayloadsPerParam ?? 10;
          const perParam = new Map<string, Set<string>>();
          const uniqueStored: typeof storedPayloads = [];
          for (const p of storedPayloads) {
            const paramKey = String(p.target_param ?? '');
            if (!perParam.has(paramKey)) perParam.set(paramKey, new Set());
            const seen = perParam.get(paramKey)!;
            if (seen.has(p.payload)) continue;
            if (seen.size >= maxPerParam) continue;
            seen.add(p.payload);
            uniqueStored.push(p);
          }

          // Fuzz in stored mode
          try {
            const fuzzResp = await this.fuzzerClient.test({
              url: actionUrl,
              payloads: uniqueStored,
              verifyExecution: false,       // skip browser verify for stored
              timeout: scan.options.timeout ?? 60000,
              storedMode: true,
              displayUrl,
              formFields: defaultFields,
            });

            const storedVulns = fuzzResp.results.filter((r) => r.vuln);
            for (const r of storedVulns) {
              const vuln = this.reportService.buildVuln(scanId, displayUrl, r);
              if (this.scanService.addVuln(scanId, vuln)) {
                this.gateway.emitFinding({ scanId, vuln });
              }
            }
            totalVulnsFound += storedVulns.length;
            totalPayloadsTested += uniqueStored.length;

            this.logger.log(
              `stored XSS form: ${storedVulns.length} vulns found ` +
              `(${uniqueStored.length} payloads tested)`,
            );
          } catch (err) {
            const detail = err instanceof Error ? err.message : 'fuzzer error';
            this.logger.warn(`stored XSS fuzzer failed: ${detail}, skipping`);
          }
        }
      }

      // ── Phase 5: REPORT ─────────────────────────────────────────────
      this.scanService.updateStatus(
        scanId,
        ScanStatus.REPORTING,
        ScanPhase.REPORT,
        90,
      );
      const vulns = this.scanService.getVulns(scanId);
      const reportUrl = await this.reportService.generate(
        scanId,
        scan,
        vulns,
        scan.options.reportFormat ?? ['html', 'json', 'pdf'],
      );

      this.scanService.updateStatus(
        scanId,
        ScanStatus.DONE,
        ScanPhase.REPORT,
        100,
      );

      const durationMs = Date.now() - startedAt;
      this.gateway.emitComplete({
        scanId,
        summary: {
          totalParams: totalUniqueParams,
          paramsTested: totalPayloadsTested,
          vulnsFound: vulns.length,
          durationMs,
        },
        reportUrl,
      });

      this.logger.log(
        `scan complete scanId=${scanId} targets=${totalTargets} vulns=${vulns.length} ms=${durationMs}`,
      );
    } catch (err: unknown) {
      const msg: string = err instanceof Error ? err.message : 'unknown error';
      this.logger.error(`scan failed scanId=${scanId} error=${msg}`);
      this.scanService.markFailed(scanId, msg);
      this.gateway.emitError(scanId, msg);
      // don't re-throw — scan is already marked FAILED,
      // retrying would hit "already running" guard
    }
  }
}
