import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { chromium, Browser } from 'playwright';
import { WafDetectorService } from './waf-detector.service';
import { DomAnalyzerService } from './dom-analyzer.service';
import {
  CrawlResult,
  DiscoveredParam,
} from '../common/interfaces/crawler.interface';
import { isSameDomain, isAbsoluteUrl } from '../common/utils/url.utils';

@Injectable()
export class CrawlerService implements OnModuleDestroy {
  private readonly logger = new Logger(CrawlerService.name);
  private browser: Browser | null = null;

  constructor(
    private readonly config: ConfigService,
    private readonly wafDetector: WafDetectorService,
    private readonly domAnalyzer: DomAnalyzerService,
  ) {}

  async onModuleDestroy(): Promise<void> {
    await this.closeBrowser();
  }

  private async getBrowser(): Promise<Browser> {
    if (!this.browser) {
      this.browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });
      this.logger.log('browser launched');
    }
    return this.browser;
  }

  private async closeBrowser(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.logger.log('browser closed');
    }
  }

  async crawl(
    url: string,
    depth: number,
    maxParams: number,
  ): Promise<CrawlResult> {
    const startedAt = Date.now();
    const visited = new Set<string>();
    const toVisit: { url: string; currentDepth: number }[] = [
      { url, currentDepth: 0 },
    ];
    const allParams: DiscoveredParam[] = [];
    const allForms: import('../common/interfaces/crawler.interface').DiscoveredForm[] = [];
    const allScripts: string[] = [];
    const paramNames = new Set<string>();
    const formKeys = new Set<string>();

    // hard caps to prevent runaway crawls on large sites
    const maxUrls = Math.max(
      this.config.get<number>('CRAWLER_MAX_URLS', 80),
      10,
    );
    const crawlTimeoutMs = this.config.get<number>(
      'CRAWLER_TIMEOUT_MS',
      60000,
    );
    const visitedPatterns = new Map<string, number>();

    const browser = await this.getBrowser();
    const context = await browser.newContext({
      userAgent: this.config.get<string>(
        'CRAWLER_USER_AGENT',
        'RedSentinel/1.0 (Security Scanner)',
      ),
      ignoreHTTPSErrors: true,
    });

    // capture waf on the first request
    let wafResult = {
      detected: false,
      name: null as string | null,
      confidence: 0,
    };
    let wafChecked = false;

    try {
      while (
        toVisit.length > 0 &&
        paramNames.size < maxParams &&
        visited.size < maxUrls &&
        Date.now() - startedAt < crawlTimeoutMs
      ) {
        const item = toVisit.shift()!;
        const normalized = this.normalizeForVisit(item.url);

        if (visited.has(normalized)) continue;

        // deduplicate URL patterns (e.g. /user/view/X — only crawl a few per pattern)
        // Allow up to MAX_PER_PATTERN pages per pattern so different challenge
        // pages (e.g. /missions/basic/1/ vs /missions/basic/2/) are not skipped.
        const MAX_PER_PATTERN = 5;
        const pattern = this.urlToPattern(item.url);
        const patternCount = visitedPatterns.get(pattern) ?? 0;
        if (patternCount >= MAX_PER_PATTERN && item.currentDepth > 0) continue;
        visitedPatterns.set(pattern, patternCount + 1);

        visited.add(normalized);

        this.logger.debug(`crawling: ${item.url} (depth=${item.currentDepth})`);

        const page = await context.newPage();
        try {
          const response = await page.goto(item.url, {
            waitUntil: 'domcontentloaded',
            timeout: 15000,
          });

          if (!response) continue;

          // waf detection on first response
          if (!wafChecked) {
            const headers: Record<string, string> = {};
            const responseHeaders = response.headers();
            for (const [k, v] of Object.entries(responseHeaders)) {
              headers[k.toLowerCase()] = v;
            }
            const cookies = await context.cookies();
            const cookieStrings = cookies.map((c) => `${c.name}=${c.value}`);
            const body = await page.content();
            wafResult = this.wafDetector.detect(headers, body, cookieStrings);
            wafChecked = true;
          }

          // Process every frame Playwright has already loaded — main frame,
          // static iframes, dynamically injected iframes, nested iframes.
          // This is more robust than parsing iframe[src] attributes because it
          // works regardless of how the frame was created.
          const frames = page.frames();
          for (const frame of frames) {
            const frameUrl = frame.url();
            if (!frameUrl || frameUrl === 'about:blank') continue;

            // Mark the frame's own URL visited so the crawl queue doesn't
            // re-fetch it as a separate top-level page later.
            visited.add(this.normalizeForVisit(frameUrl));

            let frameHtml: string;
            try {
              frameHtml = await frame.content();
            } catch {
              // cross-origin or detached frame — skip
              continue;
            }

            const effectiveUrl = frameUrl || item.url;

            // extract params
            const frameParams = this.domAnalyzer.extractParams(effectiveUrl, frameHtml);
            for (const p of frameParams) {
              if (!paramNames.has(p.name) && paramNames.size < maxParams) {
                paramNames.add(p.name);
                allParams.push(p);
              }
            }

            // extract forms
            const frameForms = this.domAnalyzer.extractForms(frameHtml, effectiveUrl);
            for (const form of frameForms) {
              const formKey = `${form.action}|${form.method}|${form.fields.sort().join(',')}`;
              if (!formKeys.has(formKey)) {
                formKeys.add(formKey);
                allForms.push(form);
              }
            }

            // extract inline scripts for dom sink analysis
            try {
              const frameScripts = await frame.evaluate(() => {
                const els = document.querySelectorAll('script:not([src])');
                return Array.from(els).map((el) => el.textContent ?? '');
              });
              allScripts.push(...frameScripts);

              // fetch same-domain external scripts
              const externalSrcs = await frame.evaluate(() =>
                Array.from(document.querySelectorAll('script[src]')).map(
                  (el) => el.getAttribute('src') ?? '',
                ),
              );
              for (const src of externalSrcs) {
                try {
                  const absUrl = new URL(src, effectiveUrl).toString();
                  if (isSameDomain(url, absUrl)) {
                    const text = await frame.evaluate(async (scriptUrl: string) => {
                      const r = await fetch(scriptUrl);
                      return r.text();
                    }, absUrl);
                    allScripts.push(text);
                  }
                } catch {
                  // unreachable script
                }
              }
            } catch {
              // frame became detached during script extraction
            }
          }

          // discover links for further crawling — collect from all same-origin frames
          if (item.currentDepth < depth) {
            for (const frame of frames) {
              const frameUrl = frame.url();
              if (!frameUrl || !isSameDomain(url, frameUrl)) continue;
              try {
                const links = await frame.evaluate(() =>
                  Array.from(document.querySelectorAll('a[href]')).map(
                    (a) => (a as HTMLAnchorElement).href,
                  ),
                );
                for (const link of links) {
                  if (
                    isAbsoluteUrl(link) &&
                    isSameDomain(url, link) &&
                    !visited.has(this.normalizeForVisit(link))
                  ) {
                    toVisit.push({ url: link, currentDepth: item.currentDepth + 1 });
                  }
                }
              } catch {
                // cross-origin frame
              }
            }
          }
        } catch (err) {
          const errorMessage = err instanceof Error ? err.message : 'unknown';
          this.logger.warn(`failed to crawl ${item.url}: ${errorMessage}`);
        } finally {
          await page.close();
        }
      }

      // analyze dom sinks across all collected scripts
      const domSinks = this.domAnalyzer.scanDomSinks(allScripts);

      // extract forms from last visited pages

      const durationMs = Date.now() - startedAt;
      const result: CrawlResult = {
        baseUrl: url,
        urls: Array.from(visited),
        params: allParams,
        forms: allForms,
        domSinks,
        waf: wafResult,
        durationMs,
      };

      this.logger.log(
        `crawl complete: ${visited.size} urls, ${allParams.length} params, ${domSinks.length} sinks, ${durationMs}ms`,
      );

      return result;
    } finally {
      await context.close();
    }
  }

  private normalizeForVisit(raw: string): string {
    try {
      const u = new URL(raw);
      u.hash = '';
      return u.toString().replace(/\/$/, '');
    } catch {
      return raw;
    }
  }

  /**
   * convert a URL to a structural pattern for deduplication.
   * replaces path segments that look like IDs/slugs with placeholders.
   * e.g. /user/view/JohnDoe → /user/view/{slug}
   *      /com/report/101608 → /com/report/{id}
   */
  private urlToPattern(raw: string): string {
    try {
      const u = new URL(raw);
      const segments = u.pathname.split('/').map((seg) => {
        if (!seg) return seg;
        if (/^\d+$/.test(seg)) return '{id}';
        if (/^[a-f0-9-]{8,}$/i.test(seg)) return '{uuid}';
        // treat trailing slugs (mixed case, numbers, special chars) as dynamic
        if (seg.length > 3 && /[A-Z]/.test(seg) && /[a-z]/.test(seg))
          return '{slug}';
        return seg;
      });
      return `${u.origin}${segments.join('/')}`;
    } catch {
      return raw;
    }
  }
}
