import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { chromium, Browser, BrowserContext, Page } from 'playwright';
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

  async crawl(url: string, depth: number, maxParams: number): Promise<CrawlResult> {
    const startedAt = Date.now();
    const visited = new Set<string>();
    const toVisit: { url: string; currentDepth: number }[] = [
      { url, currentDepth: 0 },
    ];
    const allParams: DiscoveredParam[] = [];
    const allScripts: string[] = [];
    const paramNames = new Set<string>();

    const browser = await this.getBrowser();
    const context = await browser.newContext({
      userAgent: this.config.get<string>(
        'CRAWLER_USER_AGENT',
        'RedSentinel/1.0 (Security Scanner)',
      ),
      ignoreHTTPSErrors: true,
    });

    // capture waf on the first request
    let wafResult = { detected: false, name: null as string | null, confidence: 0 };
    let wafChecked = false;

    try {
      while (toVisit.length > 0 && paramNames.size < maxParams) {
        const item = toVisit.shift()!;
        const normalized = this.normalizeForVisit(item.url);

        if (visited.has(normalized)) continue;
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
            const cookieStrings = cookies.map(
              (c) => `${c.name}=${c.value}`,
            );
            const body = await page.content();
            wafResult = this.wafDetector.detect(headers, body, cookieStrings);
            wafChecked = true;
          }

          const html = await page.content();

          // extract params from this page
          const pageParams = this.domAnalyzer.extractParams(item.url, html);
          for (const p of pageParams) {
            if (!paramNames.has(p.name) && paramNames.size < maxParams) {
              paramNames.add(p.name);
              allParams.push(p);
            }
          }

          // extract inline scripts for dom sink analysis
          const scripts = await page.evaluate(() => {
            const els = document.querySelectorAll('script:not([src])');
            return Array.from(els).map((el) => el.textContent ?? '');
          });
          allScripts.push(...scripts);

          // extract external script urls for dom sink analysis
          const externalScripts = await page.evaluate(() => {
            const els = document.querySelectorAll('script[src]');
            return Array.from(els).map((el) => el.getAttribute('src') ?? '');
          });

          // fetch external scripts content
          for (const src of externalScripts) {
            try {
              const absUrl = new URL(src, item.url).toString();
              if (isSameDomain(url, absUrl)) {
                const resp = await page.evaluate(
                  async (scriptUrl: string) => {
                    const r = await fetch(scriptUrl);
                    return r.text();
                  },
                  absUrl,
                );
                allScripts.push(resp);
              }
            } catch {
              // skip unreachable scripts
            }
          }

          // discover links for further crawling
          if (item.currentDepth < depth) {
            const links = await page.evaluate(() =>
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
                toVisit.push({
                  url: link,
                  currentDepth: item.currentDepth + 1,
                });
              }
            }
          }
        } catch (err: any) {
          this.logger.warn(
            `failed to crawl ${item.url}: ${err?.message ?? 'unknown'}`,
          );
        } finally {
          await page.close();
        }
      }

      // analyze dom sinks across all collected scripts
      const domSinks = this.domAnalyzer.scanDomSinks(allScripts);

      // extract forms from last visited pages
      const forms = this.domAnalyzer.extractForms('', url); // forms already gathered via params

      const durationMs = Date.now() - startedAt;
      const result: CrawlResult = {
        baseUrl: url,
        urls: Array.from(visited),
        params: allParams,
        forms: [],
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
}
