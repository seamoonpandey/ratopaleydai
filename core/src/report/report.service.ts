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
import { v4 as uuidv4 } from 'uuid';

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
  counts: { critical: number; high: number; medium: number; low: number };
  vulns: TemplateVuln[];
}

interface TemplateVuln {
  index: number;
  param: string;
  payload: string;
  type: string;
  severity: string;
  severityClass: string;
  reflected: boolean;
  executed: boolean;
  reflectedText: string;
  executedText: string;
  reflectedBadge: string;
  executedBadge: string;
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
    return {
      id: uuidv4(),
      scanId,
      url,
      param: result.target_param,
      payload: result.payload,
      type: this.mapType(result.type),
      severity: result.evidence.browser_alert_triggered
        ? VulnSeverity.HIGH
        : VulnSeverity.MEDIUM,
      reflected: result.reflected,
      executed: result.executed,
      evidence: {
        responseCode: result.evidence.response_code,
        reflectionPosition: result.evidence.reflection_position,
        browserAlertTriggered: result.evidence.browser_alert_triggered,
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

    if (formats.includes('json')) {
      this.generateJson(reportBase, scanId, scan, vulns);
    }

    if (formats.includes('html')) {
      this.generateHtml(reportBase, data);
    }

    if (formats.includes('pdf')) {
      await this.generatePdf(reportBase, data);
    }

    this.logger.log(
      `report generated scanId=${scanId} formats=${formats.join(',')} vulns=${vulns.length}`,
    );
    return `/reports/${scanId}.html`;
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

    if (!this.browser) {
      this.browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });
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
    } finally {
      await page.close();
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

    return {
      target: scan.url,
      scanId: scan.id,
      status: scan.status,
      completedAt: scan.completedAt?.toISOString() ?? 'N/A',
      generatedAt: new Date().toISOString(),
      duration,
      depth: scan.options.depth ?? 3,
      vulnCount: vulns.length,
      hasVulns: vulns.length > 0,
      counts,
      vulns: vulns.map((v, i) => ({
        index: i + 1,
        param: v.param,
        payload: v.payload,
        type: v.type,
        severity: v.severity,
        severityClass: v.severity.toLowerCase(),
        reflected: v.reflected,
        executed: v.executed,
        reflectedText: v.reflected ? 'Yes' : 'No',
        executedText: v.executed ? 'Yes' : 'No',
        reflectedBadge: v.reflected ? 'badge-yes' : 'badge-no',
        executedBadge: v.executed ? 'badge-yes' : 'badge-no',
        evidence: v.evidence,
      })),
    };
  }

  private mapType(raw: string): VulnType {
    if (raw === 'dom_xss') return VulnType.DOM_XSS;
    if (raw === 'stored_xss') return VulnType.STORED_XSS;
    return VulnType.REFLECTED_XSS;
  }
}
