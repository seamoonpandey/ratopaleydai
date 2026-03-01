import { Injectable, Logger } from '@nestjs/common';
import {
  DiscoveredParam,
  DiscoveredForm,
  DomSink,
} from '../common/interfaces/crawler.interface';

const DOM_SINK_PATTERNS: { type: string; pattern: RegExp }[] = [
  { type: 'innerHTML', pattern: /\.innerHTML\s*=/g },
  { type: 'outerHTML', pattern: /\.outerHTML\s*=/g },
  { type: 'document.write', pattern: /document\.write\s*\(/g },
  { type: 'document.writeln', pattern: /document\.writeln\s*\(/g },
  { type: 'eval', pattern: /\beval\s*\(/g },
  { type: 'setTimeout', pattern: /setTimeout\s*\(\s*["`']/g },
  { type: 'setInterval', pattern: /setInterval\s*\(\s*["`']/g },
  { type: 'Function', pattern: /new\s+Function\s*\(/g },
  { type: 'location.href', pattern: /location\.href\s*=/g },
  { type: 'location.assign', pattern: /location\.assign\s*\(/g },
  { type: 'location.replace', pattern: /location\.replace\s*\(/g },
  { type: 'insertAdjacentHTML', pattern: /\.insertAdjacentHTML\s*\(/g },
  { type: 'src assignment', pattern: /\.src\s*=\s*[^=]/g },
  { type: 'href assignment', pattern: /\.href\s*=\s*[^=]/g },
];

const DOM_SOURCE_PATTERNS: RegExp[] = [
  /location\.hash/g,
  /location\.search/g,
  /location\.href/g,
  /document\.cookie/g,
  /document\.referrer/g,
  /window\.name/g,
  /document\.URL/g,
  /document\.documentURI/g,
];

@Injectable()
export class DomAnalyzerService {
  private readonly logger = new Logger(DomAnalyzerService.name);

  extractParams(url: string, html: string): DiscoveredParam[] {
    const params: DiscoveredParam[] = [];
    const seen = new Set<string>();

    // extract query params from url
    try {
      const u = new URL(url);
      for (const name of u.searchParams.keys()) {
        if (!seen.has(`query:${name}`)) {
          seen.add(`query:${name}`);
          params.push({ name, source: 'query', method: 'GET' });
        }
      }
    } catch {
      // skip invalid url
    }

    // extract fragment params
    try {
      const u = new URL(url);
      if (u.hash) {
        const fragParams = new URLSearchParams(u.hash.slice(1));
        for (const name of fragParams.keys()) {
          if (!seen.has(`fragment:${name}`)) {
            seen.add(`fragment:${name}`);
            params.push({ name, source: 'fragment', method: 'GET' });
          }
        }
      }
    } catch {
      // skip
    }

    // extract form fields from html
    const forms = this.extractForms(html, url);
    for (const form of forms) {
      for (const field of form.fields) {
        const key = `form:${field}`;
        if (!seen.has(key)) {
          seen.add(key);
          params.push({
            name: field,
            source: 'form',
            method: form.method,
            formAction: form.action,
          });
        }
      }
    }

    return params;
  }

  extractForms(html: string, baseUrl: string): DiscoveredForm[] {
    const forms: DiscoveredForm[] = [];
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;

    let match: RegExpExecArray | null;
    while ((match = formRegex.exec(html)) !== null) {
      const formTag = match[0];
      const formBody = match[1];

      // extract action
      const actionMatch = formTag.match(/action=["']([^"']*)["']/i);
      let action = actionMatch ? actionMatch[1] : baseUrl;
      try {
        action = new URL(action, baseUrl).toString();
      } catch {
        action = baseUrl;
      }

      // extract method
      const methodMatch = formTag.match(/method=["']([^"']*)["']/i);
      const method =
        methodMatch && methodMatch[1].toUpperCase() === 'POST'
          ? 'POST'
          : 'GET';

      // extract input names
      const fields: string[] = [];
      const inputRegex =
        /<(?:input|textarea|select)[^>]*name=["']([^"']+)["'][^>]*>/gi;
      let inputMatch: RegExpExecArray | null;
      while ((inputMatch = inputRegex.exec(formBody)) !== null) {
        const fieldName = inputMatch[1];
        if (!fields.includes(fieldName)) {
          fields.push(fieldName);
        }
      }

      if (fields.length > 0) {
        forms.push({ action, method: method as 'GET' | 'POST', fields });
      }
    }

    return forms;
  }

  scanDomSinks(scripts: string[]): DomSink[] {
    const sinks: DomSink[] = [];

    for (const script of scripts) {
      const lines = script.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        for (const { type, pattern } of DOM_SINK_PATTERNS) {
          // reset global regex lastIndex
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            // check if a tainted source feeds into this sink
            const hasTaintedSource = DOM_SOURCE_PATTERNS.some((sp) => {
              sp.lastIndex = 0;
              return sp.test(line);
            });

            sinks.push({
              type,
              snippet: line.trim().substring(0, 200),
              location: `line ${i + 1}${hasTaintedSource ? ' (tainted source)' : ''}`,
            });
          }
        }
      }
    }

    this.logger.log(`found ${sinks.length} DOM sinks`);
    return sinks;
  }
}
