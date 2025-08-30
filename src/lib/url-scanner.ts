import { IOCSet, extractIOCsWithAI, extractIOCs } from './ioc-extractor';
import { llmService } from './llm-service';

export interface URLScanResult {
  url: string;
  title?: string;
  content: string;
  contentType?: string;
  statusCode: number;
  iocs: IOCSet;
  threatAssessment?: {
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    indicators: string[];
    summary: string;
    confidence: number;
  };
  scanTime: number;
  error?: string;
}

export interface URLScanOptions {
  useAI?: boolean;
  includePrivateIPs?: boolean;
  filterLegitimate?: boolean;
  maxContentLength?: number;
  timeout?: number;
  userAgent?: string;
}

const DEFAULT_OPTIONS: URLScanOptions = {
  useAI: true,
  includePrivateIPs: false,
  filterLegitimate: true,
  maxContentLength: 50000, // 50KB limit
  timeout: 30000, // 30 seconds
  userAgent: 'IntelForge-Scanner/1.0'
};

// Enhanced content extraction patterns for threat intelligence
const THREAT_INDICATORS = [
  // Malware indicators
  /\b(malware|trojan|backdoor|ransomware|rootkit|keylogger|stealer|loader|dropper)\b/gi,
  /\b(payload|exploit|vulnerability|CVE-\d{4}-\d{4,})\b/gi,
  
  // C2 and infrastructure indicators
  /\b(command.{0,10}control|c2|c&c|botnet|infrastructure)\b/gi,
  /\b(exfiltration|data.{0,10}theft|credential.{0,10}harvesting)\b/gi,
  
  // Attack techniques
  /\b(phishing|spear.{0,10}phishing|social.{0,10}engineering)\b/gi,
  /\b(lateral.{0,10}movement|privilege.{0,10}escalation|persistence)\b/gi,
  /\b(injection|xss|csrf|rce|lfi|rfi|sqli)\b/gi,
  
  // Threat actor indicators
  /\b(apt|advanced.{0,10}persistent.{0,10}threat|threat.{0,10}actor|cybercriminal)\b/gi,
  /\b(campaign|operation|attribution|tactics)\b/gi
];

const BENIGN_INDICATORS = [
  // Common website elements
  /\b(cookie|privacy|terms|about|contact|support|help|faq)\b/gi,
  /\b(newsletter|subscribe|login|register|cart|checkout)\b/gi,
  /\b(navigation|menu|footer|header|sidebar)\b/gi,
  
  // Legitimate services
  /\b(analytics|tracking|advertisement|marketing|social.{0,10}media)\b/gi,
  /\b(cdn|content.{0,10}delivery|bootstrap|jquery|font)\b/gi
];

export class URLScanner {
  private options: URLScanOptions;

  constructor(options: Partial<URLScanOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  async scanURL(url: string, customOptions?: Partial<URLScanOptions>): Promise<URLScanResult> {
    const startTime = Date.now();
    const opts = { ...this.options, ...customOptions };
    
    try {
      // Validate URL
      const parsedUrl = new URL(url);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Only HTTP and HTTPS URLs are supported');
      }

      // Fetch content with multiple fallback methods
      const content = await this.fetchContent(url, opts);
      
      // Extract IOCs from content
      const iocs = opts.useAI 
        ? await extractIOCsWithAI(content, opts.includePrivateIPs, opts.filterLegitimate, url)
        : extractIOCs(content, opts.includePrivateIPs, opts.filterLegitimate, url);

      // Perform AI-powered threat assessment if enabled
      let threatAssessment;
      if (opts.useAI) {
        threatAssessment = await this.assessThreatLevel(url, content, iocs);
      }

      const scanTime = Date.now() - startTime;

      return {
        url,
        content: content.substring(0, opts.maxContentLength || 50000),
        statusCode: 200,
        iocs,
        threatAssessment,
        scanTime,
        title: this.extractTitle(content)
      };

    } catch (error: any) {
      return {
        url,
        content: '',
        statusCode: 0,
        iocs: { ipv4: [], ipv6: [], domains: [], urls: [], sha256: [], md5: [], emails: [] },
        scanTime: Date.now() - startTime,
        error: error.message
      };
    }
  }

  private async fetchContent(url: string, opts: URLScanOptions): Promise<string> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), opts.timeout);

    try {
      // Try direct fetch first
      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': opts.userAgent || DEFAULT_OPTIONS.userAgent!
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const content = await response.text();
      return content;

    } catch (error: any) {
      // Fallback to CORS proxy services
      const fallbackUrls = [
        `https://r.jina.ai/${url}`,
        `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`,
      ];

      for (const fallbackUrl of fallbackUrls) {
        try {
          const response = await fetch(fallbackUrl, {
            signal: controller.signal
          });

          if (response.ok) {
            const data = await response.text();
            
            // Handle different proxy response formats
            if (fallbackUrl.includes('allorigins')) {
              const parsed = JSON.parse(data);
              return parsed.contents || '';
            }
            
            return data;
          }
        } catch (fallbackError) {
          continue;
        }
      }

      throw new Error(`Failed to fetch URL: ${error.message}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private extractTitle(content: string): string | undefined {
    const titleMatch = content.match(/<title[^>]*>([^<]+)<\/title>/i);
    return titleMatch ? titleMatch[1].trim() : undefined;
  }

  private async assessThreatLevel(url: string, content: string, iocs: IOCSet): Promise<URLScanResult['threatAssessment']> {
    try {
      const hasConfiguredProviders = await llmService.hasConfiguredProviders();
      if (!hasConfiguredProviders) {
        return this.basicThreatAssessment(content, iocs);
      }

      const iocCount = Object.values(iocs).reduce((sum, arr) => sum + arr.length, 0);
      const contentPreview = content.substring(0, 2000);

      const response = await llmService.generateCQL({
        systemPrompt: `You are a cybersecurity expert analyzing web content for threat indicators. Assess the threat level and provide analysis.

Respond with ONLY a JSON object in this exact format:
{
  "riskLevel": "low|medium|high|critical",
  "indicators": ["indicator1", "indicator2"],
  "summary": "Brief threat assessment summary",
  "confidence": 0.85
}`,
        userPrompt: `Analyze this URL and content for cybersecurity threats:

URL: ${url}
IOCs Found: ${iocCount} total
Content Preview: ${contentPreview}

Consider:
- Malicious indicators (malware, C2, phishing, exploits)
- Suspicious patterns or behaviors
- Domain reputation and hosting
- Content context and legitimacy

Provide threat assessment with confidence score (0.0-1.0).`,
        preferredModel: 'claude-3-haiku-20240307',
        maxTokens: 500,
        temperature: 0.1
      });

      const jsonMatch = response.content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }

      return this.basicThreatAssessment(content, iocs);

    } catch (error) {
      console.warn('AI threat assessment failed, using basic assessment:', error);
      return this.basicThreatAssessment(content, iocs);
    }
  }

  private basicThreatAssessment(content: string, iocs: IOCSet): URLScanResult['threatAssessment'] {
    const threatCount = THREAT_INDICATORS.reduce((count, pattern) => {
      return count + (content.match(pattern) || []).length;
    }, 0);

    const benignCount = BENIGN_INDICATORS.reduce((count, pattern) => {
      return count + (content.match(pattern) || []).length;
    }, 0);

    const iocCount = Object.values(iocs).reduce((sum, arr) => sum + arr.length, 0);
    
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    let confidence = 0.6;
    const indicators: string[] = [];

    if (iocCount > 10) {
      riskLevel = 'high';
      indicators.push(`${iocCount} IOCs detected`);
      confidence += 0.2;
    } else if (iocCount > 5) {
      riskLevel = 'medium';
      indicators.push(`${iocCount} IOCs detected`);
      confidence += 0.1;
    }

    if (threatCount > benignCount * 2) {
      riskLevel = riskLevel === 'low' ? 'medium' : 'high';
      indicators.push('High threat indicator density');
      confidence += 0.15;
    }

    if (threatCount > 5) {
      indicators.push('Multiple threat keywords found');
    }

    return {
      riskLevel,
      indicators,
      summary: `Basic pattern analysis: ${threatCount} threat indicators, ${iocCount} IOCs`,
      confidence: Math.min(confidence, 0.95)
    };
  }

  async scanMultipleURLs(urls: string[], options?: Partial<URLScanOptions>): Promise<URLScanResult[]> {
    const results = await Promise.allSettled(
      urls.map(url => this.scanURL(url, options))
    );

    return results.map((result, index) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        return {
          url: urls[index],
          content: '',
          statusCode: 0,
          iocs: { ipv4: [], ipv6: [], domains: [], urls: [], sha256: [], md5: [], emails: [] },
          scanTime: 0,
          error: result.reason?.message || 'Unknown error'
        };
      }
    });
  }
}

// Export singleton instance
export const urlScanner = new URLScanner();
