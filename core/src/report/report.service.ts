import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import * as Handlebars from 'handlebars';
import * as puppeteer from 'puppeteer';
import { ScanRecord } from '../common/interfaces/scan.interface';
import {
  Vuln,
  VulnType,
  VulnSeverity,
} from '../common/interfaces/vuln.interface';
import { FuzzResult } from '../modules-bridge/fuzzer-client.service';
import { randomUUID as uuidv4 } from 'crypto';
import { scoreFinding, deriveSink, deriveSource } from '../common/utils/severity-scorer';

interface TemplateData {
  target: string;
  scanId: string;
  status: string;
  completedAt: string;
  generatedAt: string;
  duration: string;
  depth: number;
  vulnCount: number;
  hasVulns: boolean;
  riskLevel: string;
  riskClass: string;
  riskSummary: string;
  counts: { critical: number; high: number; medium: number; low: number };
  affectedPages: string[];
  affectedPageCount: number;
  vulns: TemplateVuln[];
}

interface TemplateVuln {
  index: number;
  url: string;
  param: string;
  payload: string;
  type: string;
  typeFriendly: string;
  typeExplanation: string;
  severity: string;
  severityClass: string;
  severityExplanation: string;
  reflected: boolean;
  executed: boolean;
  confirmedDangerous: boolean;
  reflectedText: string;
  executedText: string;
  reflectedBadge: string;
  executedBadge: string;
  whatHappened: string;
  howToFix: string;
  evidence: {
    responseCode: number;
    reflectionPosition: string;
    browserAlertTriggered: boolean;
  };
}

@Injectable()
export class ReportService implements OnModuleDestroy {
  private readonly logger = new Logger(ReportService.name);
  private readonly reportsDir = path.join(process.cwd(), 'reports');
  private readonly templatesDir = path.join(
    __dirname,
    '..',
    'report',
    'templates',
  );
  private htmlTemplate!: Handlebars.TemplateDelegate;
  private pdfTemplate!: Handlebars.TemplateDelegate;
  private browser: puppeteer.Browser | null = null;

  constructor() {
    if (!fs.existsSync(this.reportsDir)) {
      fs.mkdirSync(this.reportsDir, { recursive: true });
    }
    this.compileTemplates();
  }

  async onModuleDestroy() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  buildVuln(scanId: string, url: string, result: FuzzResult): Vuln {
    const sink = deriveSink(
      result.evidence.reflection_position,
      result.evidence.sink,
    );
    const source = deriveSource(result.evidence.source);

    const { severity } = scoreFinding({
      reflected: result.reflected,
      executed: result.executed,
      payload: result.payload,
      source,
      sink,
      exactMatch: result.evidence.exact_match ?? false,
      browserAlertTriggered: result.evidence.browser_alert_triggered,
    });

    return {
      id: uuidv4(),
      scanId,
      url,
      param: result.target_param,
      payload: result.payload,
      type: this.mapType(result.type),
      severity,
      reflected: result.reflected,
      executed: result.executed,
      evidence: {
        responseCode: result.evidence.response_code,
        reflectionPosition: result.evidence.reflection_position,
        browserAlertTriggered: result.evidence.browser_alert_triggered,
        exactMatch: result.evidence.exact_match ?? false,
        sink,
        source,
        ...(result.evidence.line !== undefined && { line: result.evidence.line }),
        ...(result.evidence.snippet !== undefined && { snippet: result.evidence.snippet }),
        ...(result.evidence.script_url !== undefined && { scriptUrl: result.evidence.script_url }),
      },
      discoveredAt: new Date(),
    };
  }

  async generate(
    scanId: string,
    scan: ScanRecord,
    vulns: Vuln[],
    formats: string[],
  ): Promise<string> {
    const reportBase = path.join(this.reportsDir, scanId);
    const data = this.buildTemplateData(scan, vulns);
    const generated: string[] = [];
    const failed: string[] = [];

    if (formats.includes('json')) {
      try {
        this.generateJson(reportBase, scanId, scan, vulns);
        generated.push('json');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`json report failed scanId=${scanId}: ${msg}`);
        failed.push('json');
      }
    }

    if (formats.includes('html')) {
      try {
        this.generateHtml(reportBase, data);
        generated.push('html');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`html report failed scanId=${scanId}: ${msg}`);
        failed.push('html');
      }
    }

    if (formats.includes('pdf')) {
      try {
        await this.generatePdf(reportBase, data);
        generated.push('pdf');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(
          `pdf report failed scanId=${scanId} (puppeteer/chromium unavailable?): ${msg}`,
        );
        failed.push('pdf');
      }
    }

    this.logger.log(
      `report generated scanId=${scanId} formats=[${generated.join(',')}]${failed.length ? ` skipped=[${failed.join(',')}]` : ''} vulns=${vulns.length}`,
    );

    // Return the best available report link
    if (generated.includes('html')) return `/reports/${scanId}.html`;
    if (generated.includes('json')) return `/reports/${scanId}.json`;
    if (generated.includes('pdf')) return `/reports/${scanId}.pdf`;
    return '';
  }

  getReportPath(scanId: string, format: string): string | null {
    const filePath = path.join(this.reportsDir, `${scanId}.${format}`);
    return fs.existsSync(filePath) ? filePath : null;
  }

  getAvailableFormats(scanId: string): string[] {
    const formats: string[] = [];
    for (const ext of ['html', 'json', 'pdf']) {
      if (fs.existsSync(path.join(this.reportsDir, `${scanId}.${ext}`))) {
        formats.push(ext);
      }
    }
    return formats;
  }

  private generateJson(
    reportBase: string,
    scanId: string,
    scan: ScanRecord,
    vulns: Vuln[],
  ): void {
    const report = {
      meta: {
        scanId,
        target: scan.url,
        status: scan.status,
        createdAt: scan.createdAt.toISOString(),
        completedAt: scan.completedAt?.toISOString() ?? null,
        options: scan.options,
        generatedAt: new Date().toISOString(),
        version: '0.1.0',
      },
      summary: {
        totalVulns: vulns.length,
        critical: vulns.filter((v) => v.severity === VulnSeverity.CRITICAL)
          .length,
        high: vulns.filter((v) => v.severity === VulnSeverity.HIGH).length,
        medium: vulns.filter((v) => v.severity === VulnSeverity.MEDIUM).length,
        low: vulns.filter((v) => v.severity === VulnSeverity.LOW).length,
      },
      vulnerabilities: vulns.map((v) => ({
        id: v.id,
        param: v.param,
        payload: v.payload,
        type: v.type,
        severity: v.severity,
        url: v.url,
        reflected: v.reflected,
        executed: v.executed,
        evidence: v.evidence,
        discoveredAt: v.discoveredAt.toISOString(),
      })),
    };
    fs.writeFileSync(`${reportBase}.json`, JSON.stringify(report, null, 2), 'utf-8');
  }

  private generateHtml(reportBase: string, data: TemplateData): void {
    const html = this.htmlTemplate(data);
    fs.writeFileSync(`${reportBase}.html`, html, 'utf-8');
  }

  private async generatePdf(
    reportBase: string,
    data: TemplateData,
  ): Promise<void> {
    const html = this.pdfTemplate(data);

    try {
      if (!this.browser) {
        this.browser = await puppeteer.launch({
          headless: true,
          args: ['--no-sandbox', '--disable-setuid-sandbox'],
        });
      }
    } catch (err) {
      // Reset so the next attempt can try launching again
      this.browser = null;
      throw err;
    }

    const page = await this.browser.newPage();
    try {
      await page.setContent(html, { waitUntil: 'networkidle0' });
      const pdfBuffer = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: { top: '15mm', right: '12mm', bottom: '15mm', left: '12mm' },
      });
      fs.writeFileSync(`${reportBase}.pdf`, pdfBuffer);
    } catch (err) {
      // If the browser session is broken, close it so next scan gets a fresh one
      try {
        await this.browser.close();
      } catch {
        /* ignore close error */
      }
      this.browser = null;
      throw err;
    } finally {
      try {
        await page.close();
      } catch {
        /* ignore */
      }
    }
  }

  private compileTemplates(): void {
    const htmlPath = path.join(this.templatesDir, 'report.html.hbs');
    const pdfPath = path.join(this.templatesDir, 'report.pdf.hbs');

    if (fs.existsSync(htmlPath)) {
      this.htmlTemplate = Handlebars.compile(
        fs.readFileSync(htmlPath, 'utf-8'),
      );
    } else {
      this.htmlTemplate = Handlebars.compile(
        '<html><body><h1>Report</h1><pre>{{json}}</pre></body></html>',
      );
      this.logger.warn(`html template not found at ${htmlPath}`);
    }

    if (fs.existsSync(pdfPath)) {
      this.pdfTemplate = Handlebars.compile(
        fs.readFileSync(pdfPath, 'utf-8'),
      );
    } else {
      this.pdfTemplate = this.htmlTemplate;
      this.logger.warn(`pdf template not found at ${pdfPath}, using html`);
    }
  }

  private buildTemplateData(scan: ScanRecord, vulns: Vuln[]): TemplateData {
    const counts = {
      critical: vulns.filter((v) => v.severity === VulnSeverity.CRITICAL)
        .length,
      high: vulns.filter((v) => v.severity === VulnSeverity.HIGH).length,
      medium: vulns.filter((v) => v.severity === VulnSeverity.MEDIUM).length,
      low: vulns.filter((v) => v.severity === VulnSeverity.LOW).length,
    };

    const duration = scan.completedAt
      ? `${((scan.completedAt.getTime() - scan.createdAt.getTime()) / 1000).toFixed(1)}s`
      : 'N/A';

    // Determine overall risk level
    let riskLevel = 'None';
    let riskClass = 'none';
    let riskSummary = 'No vulnerabilities were found during this scan.';
    if (counts.critical > 0) {
      riskLevel = 'Critical';
      riskClass = 'critical';
      riskSummary = `Your website has ${counts.critical} critical security issue${counts.critical > 1 ? 's' : ''} that could allow attackers to steal user data or take over accounts. Immediate action is required.`;
    } else if (counts.high > 0) {
      riskLevel = 'High';
      riskClass = 'high';
      riskSummary = `Your website has ${counts.high} high-severity issue${counts.high > 1 ? 's' : ''} that could be exploited to run malicious code in visitors' browsers. These should be fixed as soon as possible.`;
    } else if (counts.medium > 0) {
      riskLevel = 'Medium';
      riskClass = 'medium';
      riskSummary = `Your website has ${counts.medium} medium-severity issue${counts.medium > 1 ? 's' : ''} where user input is reflected without proper safety measures. These should be addressed in your next update.`;
    } else if (counts.low > 0) {
      riskLevel = 'Low';
      riskClass = 'low';
      riskSummary = `Your website has ${counts.low} low-severity finding${counts.low > 1 ? 's' : ''}. While not immediately dangerous, fixing them will improve your overall security.`;
    }

    // Collect unique affected pages
    const affectedPages = [...new Set(vulns.map((v) => v.url))];

    return {
      target: scan.url,
      scanId: scan.id,
      status: scan.status,
      completedAt: scan.completedAt
        ? scan.completedAt.toLocaleString('en-US', {
            dateStyle: 'medium',
            timeStyle: 'short',
          })
        : 'N/A',
      generatedAt: new Date().toLocaleString('en-US', {
        dateStyle: 'medium',
        timeStyle: 'short',
      }),
      duration,
      depth: scan.options.depth ?? 3,
      vulnCount: vulns.length,
      hasVulns: vulns.length > 0,
      riskLevel,
      riskClass,
      riskSummary,
      counts,
      affectedPages,
      affectedPageCount: affectedPages.length,
      vulns: vulns.map((v, i) => ({
        index: i + 1,
        url: v.url,
        param: v.param,
        payload: v.payload,
        type: v.type,
        typeFriendly: this.friendlyType(v.type),
        typeExplanation: this.typeExplanation(v.type),
        severity: v.severity,
        severityClass: v.severity.toLowerCase(),
        severityExplanation: this.severityExplanation(v.severity),
        reflected: v.reflected,
        executed: v.executed,
        confirmedDangerous: v.executed && v.evidence.browserAlertTriggered,
        reflectedText: v.reflected ? 'Yes' : 'No',
        executedText: v.executed ? 'Yes' : 'No',
        reflectedBadge: v.reflected ? 'badge-yes' : 'badge-no',
        executedBadge: v.executed ? 'badge-yes' : 'badge-no',
        whatHappened: this.whatHappened(v),
        howToFix: this.howToFix(v),
        evidence: v.evidence,
      })),
    };
  }

  private friendlyType(type: string): string {
    switch (type) {
      case VulnType.REFLECTED_XSS:
        return 'Reflected Cross-Site Scripting (XSS)';
      case VulnType.STORED_XSS:
        return 'Stored Cross-Site Scripting (XSS)';
      case VulnType.DOM_XSS:
        return 'DOM-Based Cross-Site Scripting (XSS)';
      default:
        return 'Cross-Site Scripting (XSS)';
    }
  }

  private typeExplanation(type: string): string {
    switch (type) {
      case VulnType.REFLECTED_XSS:
        return 'The website takes input from the URL and displays it back on the page without cleaning it. An attacker can craft a malicious link that, when clicked by a user, runs harmful code in their browser.';
      case VulnType.STORED_XSS:
        return 'Malicious input submitted to the website gets saved (e.g. in a database) and later displayed to other users. Every visitor who views the affected page runs the attacker\'s code automatically.';
      case VulnType.DOM_XSS:
        return 'The page\'s JavaScript code reads data from the URL or user input and inserts it into the page unsafely. This allows an attacker to inject code that runs in the visitor\'s browser.';
      default:
        return 'The website does not properly clean user input before displaying it, allowing attackers to inject malicious code.';
    }
  }

  private severityExplanation(severity: VulnSeverity): string {
    switch (severity) {
      case VulnSeverity.CRITICAL:
        return 'Confirmed exploitable — an attacker can steal session cookies, passwords, or take over user accounts.';
      case VulnSeverity.HIGH:
        return 'Confirmed that malicious code executes in the browser. An attacker could steal information or perform actions on behalf of users.';
      case VulnSeverity.MEDIUM:
        return 'The input appears on the page but code execution was not fully confirmed. Still a risk if combined with other techniques.';
      case VulnSeverity.LOW:
        return 'Minor issue that could become exploitable under specific conditions.';
      default:
        return 'Informational finding.';
    }
  }

  private whatHappened(v: Vuln): string {
    const paramDesc = `the "${v.param}" field`;
    if (v.executed && v.evidence.browserAlertTriggered) {
      return `We sent test code through ${paramDesc} and the website ran it in a real browser. This proves an attacker could inject any script through this field.`;
    }
    if (v.executed) {
      return `We sent test code through ${paramDesc} and detected that JavaScript executed. An attacker could use this to run malicious scripts on your users' browsers.`;
    }
    if (v.reflected) {
      return `We sent test code through ${paramDesc} and the website displayed it back without removing the dangerous parts. This means an attacker's code could be injected into the page.`;
    }
    return `A potential injection point was found through ${paramDesc}.`;
  }

  private howToFix(v: Vuln): string {
    const fixes: string[] = [];
    switch (v.type) {
      case VulnType.REFLECTED_XSS:
        fixes.push(
          'Encode all user input before displaying it on the page (use HTML entity encoding).',
          'Implement a Content Security Policy (CSP) header to block inline scripts.',
          `Validate and sanitize the "${v.param}" parameter on the server side before using it in HTML.`,
        );
        break;
      case VulnType.STORED_XSS:
        fixes.push(
          'Sanitize all user-submitted content before storing it in the database.',
          'Encode stored content when rendering it on the page.',
          'Implement a Content Security Policy (CSP) header.',
        );
        break;
      case VulnType.DOM_XSS:
        fixes.push(
          'Avoid using innerHTML, document.write(), or eval() with user-controlled data.',
          'Use textContent or createElement() instead of innerHTML for inserting user data.',
          'Implement a strict Content Security Policy (CSP).',
        );
        break;
      default:
        fixes.push(
          'Encode all user input before displaying it.',
          'Implement a Content Security Policy (CSP).',
        );
    }
    return fixes.join(' ');
  }

  private mapType(raw: string): VulnType {
    if (raw === 'dom_xss') return VulnType.DOM_XSS;
    if (raw === 'open_redirect') return VulnType.DOM_XSS;
    if (raw === 'stored_xss') return VulnType.STORED_XSS;
    return VulnType.REFLECTED_XSS;
  }
}
