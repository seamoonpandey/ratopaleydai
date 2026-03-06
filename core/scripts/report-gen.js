#!/usr/bin/env node
/**
 * RedSentinel — Standalone Report Generator
 * ==========================================
 * Regenerates HTML and/or PDF reports from existing JSON report files.
 * Runs completely independently — no NestJS app or database needed.
 *
 * Usage:
 *   node scripts/report-gen.js --id <scanId>              # one scan
 *   node scripts/report-gen.js --id <id1> --id <id2>      # multiple scans
 *   node scripts/report-gen.js --all                       # every scan with JSON
 *   node scripts/report-gen.js --broken                    # only empty/broken HTML
 *   node scripts/report-gen.js --input /path/to/report.json  # arbitrary JSON file
 *
 * Options:
 *   --format html,pdf   Comma-separated formats to generate (default: html,pdf)
 *   --reports-dir <dir> Path to reports directory         (default: ./reports)
 *   --out <dir>         Output directory                  (default: <reports-dir>)
 *   --no-pdf            Skip PDF generation (faster)
 *   --help              Show this help text
 */

'use strict';

const path  = require('path');
const fs    = require('fs');

// ── Dependency check ─────────────────────────────────────────────────────────

let Handlebars, puppeteer;
try {
  Handlebars = require('handlebars');
} catch {
  console.error('[error] handlebars not found. Run: npm install (inside core/)');
  process.exit(1);
}
try {
  puppeteer = require('puppeteer');
} catch {
  // PDF will be skipped if puppeteer is missing
  puppeteer = null;
}

// ── CLI argument parsing ──────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { ids: [], all: false, broken: false, input: null, formats: ['html', 'pdf'], reportsDir: null, outDir: null };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    switch (a) {
      case '--help': case '-h':
        printHelp(); process.exit(0); break;
      case '--all':
        args.all = true; i++; break;
      case '--broken':
        args.broken = true; i++; break;
      case '--no-pdf':
        args.formats = args.formats.filter(f => f !== 'pdf'); i++; break;
      case '--id':
        if (!argv[i + 1]) fatal('--id requires a value');
        args.ids.push(argv[++i]); i++; break;
      case '--input':
        if (!argv[i + 1]) fatal('--input requires a path');
        args.input = argv[++i]; i++; break;
      case '--format': case '--formats':
        if (!argv[i + 1]) fatal('--format requires a value');
        args.formats = argv[++i].split(',').map(s => s.trim().toLowerCase());
        i++; break;
      case '--reports-dir':
        if (!argv[i + 1]) fatal('--reports-dir requires a path');
        args.reportsDir = argv[++i]; i++; break;
      case '--out':
        if (!argv[i + 1]) fatal('--out requires a path');
        args.outDir = argv[++i]; i++; break;
      default:
        // bare UUID treated as --id
        if (/^[0-9a-f-]{36}$/i.test(a)) { args.ids.push(a); i++; }
        else { fatal(`unknown argument: ${a}`); }
    }
  }
  return args;
}

function printHelp() {
  console.log(`
RedSentinel Report Generator
Usage: node scripts/report-gen.js [options]

Selection (at least one required):
  --id <scanId>         Regenerate a specific scan (repeatable)
  --all                 Regenerate all scans that have a JSON file
  --broken              Regenerate only scans with empty/broken HTML
  --input <file>        Generate from an arbitrary JSON report file

Options:
  --format <fmt>        Comma-separated formats: html,pdf   [default: html,pdf]
  --no-pdf              Skip PDF generation (faster run)
  --reports-dir <path>  Reports directory                   [default: ./reports]
  --out <path>          Output directory                    [default: reports-dir]
  --help                Show this help

Examples:
  node scripts/report-gen.js --broken
  node scripts/report-gen.js --id abc-123 --format pdf
  node scripts/report-gen.js --all --no-pdf
  node scripts/report-gen.js --input /tmp/myreport.json --out /tmp
`);
}

function fatal(msg) {
  console.error(`[error] ${msg}\nRun with --help for usage.`);
  process.exit(1);
}

// ── Template resolution (mirrors report.service.ts resolveTemplatesDir) ──────

function resolveTemplatesDir() {
  const scriptDir  = __dirname;                     // core/scripts/
  const coreDir    = path.join(scriptDir, '..');    // core/
  const candidates = [
    path.join(coreDir, 'src', 'report', 'templates'),           // dev
    path.join(coreDir, 'dist', 'report', 'templates'),          // prod (compiled)
    path.join(coreDir, 'dist', 'src', 'report', 'templates'),   // alt compiled
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'report.html.hbs'))) return dir;
  }
  fatal(
    'Could not find report templates. Expected one of:\n' +
    candidates.map(d => `  ${d}`).join('\n')
  );
}

function resolveLogoDataUri() {
  const scriptDir = __dirname;
  const coreDir = path.join(scriptDir, '..');
  const candidates = [
    path.join(coreDir, 'public', 'logo.png'),
    path.join(process.cwd(), 'public', 'logo.png'),
    path.join(process.cwd(), 'core', 'public', 'logo.png'),
  ];

  for (const logoPath of candidates) {
    if (!fs.existsSync(logoPath)) continue;
    const buffer = fs.readFileSync(logoPath);
    return `data:image/png;base64,${buffer.toString('base64')}`;
  }

  return '';
}

const LOGO_DATA_URI = resolveLogoDataUri();

// ── Helper functions (mirrors report.service.ts) ──────────────────────────────

function friendlyType(type) {
  switch (type) {
    case 'reflected_xss': return 'Reflected Cross-Site Scripting (XSS)';
    case 'stored_xss':    return 'Stored Cross-Site Scripting (XSS)';
    case 'dom_xss':       return 'DOM-Based Cross-Site Scripting (XSS)';
    case 'mutation_xss':  return 'Mutation XSS (mXSS)';
    case 'blind_xss':     return 'Blind XSS';
    case 'template_injection': return 'Template Injection';
    case 'svg_xss':       return 'SVG/Polyglot XSS';
    default:              return 'Cross-Site Scripting (XSS)';
  }
}

function typeExplanation(type) {
  switch (type) {
    case 'reflected_xss':
      return 'The website takes input from the URL and displays it back on the page without cleaning it. An attacker can craft a malicious link that, when clicked by a user, runs harmful code in their browser.';
    case 'stored_xss':
      return "Malicious input submitted to the website gets saved (e.g. in a database) and later displayed to other users. Every visitor who views the affected page runs the attacker's code automatically.";
    case 'dom_xss':
      return "The page's JavaScript code reads data from the URL or user input and inserts it into the page unsafely. This allows an attacker to inject code that runs in the visitor's browser.";
    case 'mutation_xss':
      return 'The website attempts to sanitize user input, but the browser\'s HTML parser re-interprets the content differently. This allows an attacker to bypass the sanitizer using browser-specific parsing tricks (e.g., nested contexts in SVG/MathML).';
    case 'blind_xss':
      return 'Malicious input is stored on the server but never displayed to the attacker. Instead, it may appear in admin panels, logs, or notification emails viewed by other users. The attacker cannot directly verify execution but the payload still reaches the target.';
    case 'template_injection':
      return 'The website processes user input as template expressions (e.g., AngularJS {{}}). An attacker can break out of the template context and execute arbitrary JavaScript code.';
    case 'svg_xss':
      return 'SVG content is rendered with user-controlled data, allowing injection of SVG namespace events (onload, onerror) or nested script tags. SVG parsers have their own security context separate from HTML.';
    default:
      return 'The website does not properly clean user input before displaying it, allowing attackers to inject malicious code.';
  }
}

function severityExplanation(severity) {
  switch (severity) {
    case 'CRITICAL': return 'Confirmed exploitable — an attacker can steal session cookies, passwords, or take over user accounts.';
    case 'HIGH':     return 'Confirmed that malicious code executes in the browser. An attacker could steal information or perform actions on behalf of users.';
    case 'MEDIUM':   return 'The input appears on the page but code execution was not fully confirmed. Still a risk if combined with other techniques.';
    case 'LOW':      return 'Minor issue that could become exploitable under specific conditions.';
    default:         return 'Informational finding.';
  }
}

function whatHappened(v) {
  const p = `the "${v.param}" field`;
  if (v.executed && v.evidence?.browserAlertTriggered)
    return `We sent test code through ${p} and the website ran it in a real browser. This proves an attacker could inject any script through this field.`;
  if (v.executed)
    return `We sent test code through ${p} and detected that JavaScript executed. An attacker could use this to run malicious scripts on your users' browsers.`;
  if (v.reflected)
    return `We sent test code through ${p} and the website displayed it back without removing the dangerous parts. This means an attacker's code could be injected into the page.`;
  return `A potential injection point was found through ${p}.`;
}

function howToFix(v) {
  switch (v.type) {
    case 'reflected_xss': return [
      'Encode all user input before displaying it on the page (use HTML entity encoding).',
      'Implement a Content Security Policy (CSP) header to block inline scripts.',
      `Validate and sanitize the "${v.param}" parameter on the server side before using it in HTML.`,
    ].join(' ');
    case 'stored_xss': return [
      'Sanitize all user-submitted content before storing it in the database.',
      'Encode stored content when rendering it on the page.',
      'Implement a Content Security Policy (CSP) header.',
    ].join(' ');
    case 'dom_xss': return [
      'Avoid using innerHTML, document.write(), or eval() with user-controlled data.',
      'Use textContent or createElement() instead of innerHTML for inserting user data.',
      'Implement a strict Content Security Policy (CSP).',
    ].join(' ');
    case 'mutation_xss': return [
      'Use a robust HTML sanitizer library (DOMPurify, bleach) that understands namespace context.',
      'Test your sanitizer against known mXSS vectors (SVG, MathML, HTML5 shortcuts).',
      'Implement and enforce a Content Security Policy (CSP) to prevent inline script execution.',
    ].join(' ');
    case 'blind_xss': return [
      'Sanitize and encode all user input at the point of storage.',
      'Never trust data from user forms, even if it doesn\'t appear on the user-facing page.',
      'Secure admin panels and backend logs — these are common Blind XSS targets.',
    ].join(' ');
    case 'template_injection': return [
      'Never render user input as template code — use templating engine sandboxes.',
      'If using AngularJS, disable dangerous expressions in user data or use strict contextual escaping.',
      'Prefer template engines with auto-escaping enabled by default.',
    ].join(' ');
    case 'svg_xss': return [
      'If accepting user-provided SVG, parse and validate it strictly (whitelist allowed elements).',
      'Serve SVG files with content-type application/svg+xml, not text/html.',
      'Never render unsanitized SVG data directly via innerHTML or in HTML context.',
    ].join(' ');
    default: return [
      'Encode all user input before displaying it.',
      'Implement a Content Security Policy (CSP).',
    ].join(' ');
  }
}

// ── Build Handlebars template data from JSON report ───────────────────────────

function buildTemplateData(report) {
  const { meta, summary, vulnerabilities } = report;
  const counts = {
    critical: summary.critical || 0,
    high:     summary.high     || 0,
    medium:   summary.medium   || 0,
    low:      summary.low      || 0,
  };

  let riskLevel = 'None', riskClass = 'none';
  let riskSummary = 'No vulnerabilities were found during this scan.';
  if (counts.critical > 0) {
    riskLevel = 'Critical'; riskClass = 'critical';
    riskSummary = `Your website has ${counts.critical} critical security issue${counts.critical > 1 ? 's' : ''} that could allow attackers to steal user data or take over accounts. Immediate action is required.`;
  } else if (counts.high > 0) {
    riskLevel = 'High'; riskClass = 'high';
    riskSummary = `Your website has ${counts.high} high-severity issue${counts.high > 1 ? 's' : ''} that could be exploited to run malicious code in visitors' browsers. These should be fixed as soon as possible.`;
  } else if (counts.medium > 0) {
    riskLevel = 'Medium'; riskClass = 'medium';
    riskSummary = `Your website has ${counts.medium} medium-severity issue${counts.medium > 1 ? 's' : ''} where user input is reflected without proper safety measures. These should be addressed in your next update.`;
  } else if (counts.low > 0) {
    riskLevel = 'Low'; riskClass = 'low';
    riskSummary = `Your website has ${counts.low} low-severity finding${counts.low > 1 ? 's' : ''}. While not immediately dangerous, fixing them will improve your overall security.`;
  }

  const fmt = (iso) => iso
    ? new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })
    : 'N/A';

  let duration = 'N/A';
  if (meta.completedAt && meta.createdAt) {
    const ms = new Date(meta.completedAt).getTime() - new Date(meta.createdAt).getTime();
    duration = `${(ms / 1000).toFixed(1)}s`;
  }

  const affectedPages = [...new Set(vulnerabilities.map(v => v.url))];

  return {
    logoSrc:          LOGO_DATA_URI,
    target:           meta.target,
    scanId:           meta.scanId,
    status:           meta.status,
    completedAt:      fmt(meta.completedAt),
    generatedAt:      fmt(meta.generatedAt || new Date().toISOString()),
    duration,
    depth:            meta.options?.depth ?? 3,
    vulnCount:        vulnerabilities.length,
    hasVulns:         vulnerabilities.length > 0,
    riskLevel,
    riskClass,
    riskSummary,
    counts,
    affectedPages,
    affectedPageCount: affectedPages.length,
    vulns: vulnerabilities.map((v, i) => ({
      index:              i + 1,
      url:                v.url,
      param:              v.param,
      payload:            v.payload,
      type:               v.type,
      typeFriendly:       friendlyType(v.type),
      typeExplanation:    typeExplanation(v.type),
      severity:           v.severity,
      severityClass:      v.severity.toLowerCase(),
      severityExplanation: severityExplanation(v.severity),
      reflected:          v.reflected,
      executed:           v.executed,
      confirmedDangerous: v.executed && v.evidence?.browserAlertTriggered,
      reflectedText:      v.reflected ? 'Yes' : 'No',
      executedText:       v.executed  ? 'Yes' : 'No',
      reflectedBadge:     v.reflected ? 'badge-yes' : 'badge-no',
      executedBadge:      v.executed  ? 'badge-yes' : 'badge-no',
      whatHappened:       whatHappened(v),
      howToFix:           howToFix(v),
      evidence:           v.evidence,
    })),
  };
}

// ── Core generation logic ─────────────────────────────────────────────────────

const BROWSER_ARGS = ['--no-sandbox', '--disable-setuid-sandbox'];
let globalBrowser = null;

async function getBrowser() {
  if (!puppeteer) throw new Error('puppeteer not installed');
  if (!globalBrowser) {
    globalBrowser = await puppeteer.launch({ headless: true, args: BROWSER_ARGS });
  }
  return globalBrowser;
}

async function closeBrowser() {
  if (globalBrowser) {
    await globalBrowser.close().catch(() => {});
    globalBrowser = null;
  }
}

async function generateHtml(outBase, data, tpl) {
  const html = tpl(data);
  const out = `${outBase}.html`;
  fs.writeFileSync(out, html, 'utf-8');
  return { path: out, size: html.length };
}

async function generatePdf(outBase, data, tpl) {
  const html = tpl(data);
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const buf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '15mm', right: '12mm', bottom: '15mm', left: '12mm' },
    });
    const out = `${outBase}.pdf`;
    fs.writeFileSync(out, buf);
    return { path: out, size: buf.length };
  } finally {
    await page.close().catch(() => {});
  }
}

async function processReport({ jsonPath, outBase, formats, htmlTpl, pdfTpl }) {
  const report = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
  const data   = buildTemplateData(report);
  const results = { html: null, pdf: null, error: null };

  try {
    if (formats.includes('html')) {
      results.html = await generateHtml(outBase, data, htmlTpl);
    }
    if (formats.includes('pdf')) {
      results.pdf  = await generatePdf(outBase, data, pdfTpl);
    }
  } catch (err) {
    results.error = err.message;
  }

  return { scanId: report.meta.scanId, target: report.meta.target, vulns: report.vulnerabilities.length, ...results };
}

// ── Scan ID collection helpers ────────────────────────────────────────────────

const FALLBACK_HTML = '<html><body><h1>Report</h1><pre></pre></body></html>';

function isBrokenHtml(htmlPath) {
  if (!fs.existsSync(htmlPath)) return true;
  const content = fs.readFileSync(htmlPath, 'utf-8').trim();
  return content === FALLBACK_HTML || content.length < 200;
}

function collectScanIds(reportsDir, args) {
  const ids = new Set(args.ids);

  if (args.all || args.broken) {
    const jsonFiles = fs.readdirSync(reportsDir).filter(f => f.endsWith('.json'));
    for (const f of jsonFiles) {
      const scanId = path.basename(f, '.json');
      if (args.all) {
        ids.add(scanId);
      } else if (args.broken) {
        const htmlPath = path.join(reportsDir, `${scanId}.html`);
        if (isBrokenHtml(htmlPath)) ids.add(scanId);
      }
    }
  }

  return [...ids];
}

// ── Progress printing ─────────────────────────────────────────────────────────

function pad(s, n) { return String(s).padEnd(n); }

function printResult(r, i, total) {
  const idx   = `[${i + 1}/${total}]`;
  const id    = r.scanId ? r.scanId.slice(0, 8) + '…' : '?';
  const vulns = `${r.vulns} vuln${r.vulns !== 1 ? 's' : ''}`;

  if (r.error) {
    console.error(`${idx} FAIL  ${pad(id, 12)} ${r.error}`);
    return;
  }

  const parts = [];
  if (r.html) parts.push(`html ${(r.html.size / 1024).toFixed(1)}KB`);
  if (r.pdf)  parts.push(`pdf ${(r.pdf.size / 1024).toFixed(0)}KB`);
  console.log(`${idx} OK    ${pad(id, 12)} ${pad(vulns, 12)} ${parts.join('  ')}`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));

  // Resolve directories
  const reportsDir = args.reportsDir
    ? path.resolve(args.reportsDir)
    : path.join(__dirname, '..', 'reports');

  const outDir = args.outDir
    ? path.resolve(args.outDir)
    : reportsDir;

  if (!fs.existsSync(reportsDir)) fatal(`reports directory not found: ${reportsDir}`);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  // Validate at least one format
  const validFormats = ['html', 'pdf'];
  const formats = args.formats.filter(f => validFormats.includes(f));
  if (formats.length === 0) fatal('No valid formats selected. Use --format html,pdf');

  if (formats.includes('pdf') && !puppeteer) {
    console.warn('[warn] puppeteer not found — PDF will be skipped. Run: npm install');
    formats.splice(formats.indexOf('pdf'), 1);
  }

  // Compile templates
  const templatesDir = resolveTemplatesDir();
  console.log(`[info] templates: ${templatesDir}`);

  const htmlTpl = Handlebars.compile(
    fs.readFileSync(path.join(templatesDir, 'report.html.hbs'), 'utf-8')
  );
  const pdfTpl = formats.includes('pdf')
    ? Handlebars.compile(fs.readFileSync(path.join(templatesDir, 'report.pdf.hbs'), 'utf-8'))
    : null;

  // Determine items to process
  let jobs = []; // [{ jsonPath, outBase }]

  if (args.input) {
    // Single arbitrary file
    const jsonPath = path.resolve(args.input);
    if (!fs.existsSync(jsonPath)) fatal(`input file not found: ${jsonPath}`);
    const base = path.join(outDir, path.basename(jsonPath, '.json'));
    jobs.push({ jsonPath, outBase: base });
  } else {
    const scanIds = collectScanIds(reportsDir, args);
    if (scanIds.length === 0) {
      if (args.broken) {
        console.log('[info] No broken reports found — all good!');
      } else {
        fatal('No scan IDs specified. Use --id <id>, --all, --broken, or --input <file>');
      }
      return;
    }
    for (const id of scanIds) {
      const jsonPath = path.join(reportsDir, `${id}.json`);
      if (!fs.existsSync(jsonPath)) {
        console.warn(`[skip] ${id} — no JSON file found`);
        continue;
      }
      jobs.push({ jsonPath, outBase: path.join(outDir, id) });
    }
  }

  if (jobs.length === 0) { console.log('[info] Nothing to do.'); return; }

  const mode = formats.join('+');
  console.log(`[info] generating ${mode} for ${jobs.length} report${jobs.length > 1 ? 's' : ''}\n`);

  let passed = 0, failed = 0;
  for (let i = 0; i < jobs.length; i++) {
    const result = await processReport({ ...jobs[i], formats, htmlTpl, pdfTpl });
    printResult(result, i, jobs.length);
    result.error ? failed++ : passed++;
  }

  await closeBrowser();

  console.log(`\n${passed} succeeded${failed > 0 ? `, ${failed} failed` : ''} — done.`);
}

main().catch(err => {
  closeBrowser().finally(() => {
    console.error('[fatal]', err.message);
    process.exit(1);
  });
});
