export interface IOCSet {
  ipv4: string[];
  ipv6: string[];
  domains: string[];
  urls: string[];
  sha256: string[];
  md5: string[];
  emails: string[];
}

export interface IOCCounts {
  ipv4: number;
  ipv6: number;
  domains: number;
  urls: number;
  sha256: number;
  md5: number;
  emails: number;
  total: number;
}

// Regex patterns for IOC extraction
const patterns = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  url: /https?:\/\/(?:[-\w.])+(?:[:\d]+)?(?:\/(?:[\w._~!$&'()*+,;=:@%-]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w._~!$&'()*+,;=:@%-]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@%-]|%[0-9A-Fa-f]{2})*)?/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g
};

// Enhanced legitimate website patterns to filter out
const legitWebsitePatterns = [
  // Social media and common platforms
  /\b(facebook|twitter|linkedin|instagram|youtube|github|reddit|tiktok|snapchat|pinterest)\.com\b/i,
  /\b(google|microsoft|apple|amazon|cloudflare|netflix|spotify|zoom)\.com\b/i,
  /\b(stackoverflow|wikipedia|w3\.org|mozilla\.org|ietf\.org)\.com?\b/i,
  
  // Threat intel blogs and legitimate security content (expanded)
  /\baka\.ms\b/i,
  /\b(thecyberwire|krebsonsecurity|darkreading|bleepingcomputer|threatpost)\.com\b/i,
  /\b(fireeye|crowdstrike|symantec|mcafee|kaspersky|bitdefender|malwarebytes)\.com\b/i,
  /\b(mitre\.org|cve\.mitre\.org|nvd\.nist\.gov|cisa\.gov)\b/i,
  
  // CDNs and common services (expanded)
  /\b(unpkg|jsdelivr|cdnjs|googleapis|bootstrapcdn|jquery|fontawesome)\.com?\b/i,
  /\b(gravatar|disqus|addthis|shareaholic|intercom|zendesk|salesforce)\.com\b/i,
  /\b(aws\.amazon\.com|azure\.microsoft\.com|cloud\.google\.com)\b/i,
  
  // Common website infrastructure (enhanced)
  /\b(docs?\.|support\.|help\.|kb\.|faq\.|blog\.|news\.|www\.|api\.|cdn\.|static\.)[\w.-]+\.(com|org|net|edu|gov|io)\b/i,
  /\b[\w.-]+\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot|pdf|mp4|avi|mp3|webm|ogg)\b/i,
  
  // Analytics and tracking (legitimate, expanded)
  /\b(analytics\.google|googletagmanager|doubleclick|adsystem\.google|facebook\.com\/tr)\.com?\b/i,
  /\b(google-analytics|gtag|ga\.js|fbevents\.js|hotjar|mixpanel|segment)\.com?\b/i,
  
  // Common legitimate domains
  /\b(paypal|stripe|square|shopify|wordpress|wix|squarespace)\.com\b/i,
  /\b(office365|outlook|live|hotmail|gmail|yahoo|aol|icloud)\.com\b/i,
  
  // News and media sites
  /\b(cnn|bbc|reuters|ap|nytimes|wsj|forbes|techcrunch|wired)\.com\b/i,
  
  // Developer and tech platforms
  /\b(npmjs|pypi|rubygems|docker|kubernetes|terraform)\.com?\b/i,
  /\b(atlassian|slack|discord|telegram|whatsapp)\.com\b/i,
  
  // Additional benign patterns from your data
  /\b(treasury\.gov|korean-hackers|north-korean|freelance\.html)$/i,
  /\b(thehackernews\.com|auth\.university|fordham\.edu)$/i,
  /\b(palantir\.net|suite\.palantirnet\.com)$/i,
  /\b[\w.-]*\.(gov|edu|mil)$/i, // Government, education, military domains
  /\b(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i, // Local addresses
  /\b[\w.-]*\.(example|test|invalid|local)$/i // Test/example domains
];

// Enhanced benign URL paths that are likely navigation/resources
const benignUrlPaths = [
  /\/(about|contact|privacy|terms|support|help|faq|blog|news|careers|jobs|team|company)$/i,
  /\/(css|js|images?|assets?|static|media|fonts?|uploads?|downloads?)\//i,
  /\.(css|js|png|jpg|jpeg|gif|webp|svg|ico|woff|woff2|ttf|eot|pdf|mp4|avi|mp3|webm|ogg)(\?.*)?$/i,
  /\/wp-(content|includes|admin|json)\//i,
  /\/(node_modules|bower_components|vendor|dist|build)\//i,
  /\/(login|signin|signup|register|logout|auth|oauth)\b/i,
  /\/(search|browse|category|tag|archive|page|post)\b/i,
  /\/(api|ajax|json|xml|rss|feed)\b/i,
  /\/(admin|dashboard|panel|cp|cms)\b/i,
  /\/(checkout|cart|shop|store|product)\b/i,
  /\#(top|bottom|main|content|footer|header|nav|menu)\b/i,
  /\?utm_(source|medium|campaign|term|content)=/i, // UTM tracking parameters
  /\?ref=/i, // Referral parameters
  /\/(en|es|fr|de|it|pt|zh|ja|ko|ru)\//i, // Language paths
  /\/(2020|2021|2022|2023|2024|2025)\//i, // Year-based paths
  /\/authors?\//i, // Author pages
  /\/reports?\//i, // Report pages (often legitimate)
  /\/research\//i, // Research pages
  /\/whitepapers?\//i, // Whitepaper pages
  /\/case-studies?\//i, // Case study pages
  /\/resources?\//i, // Resource pages
  /\/solutions?\//i, // Solution pages
  /\/products?\//i, // Product pages
  /\/services?\//i, // Service pages
  /\/events?\//i, // Event pages
  /\/webinars?\//i, // Webinar pages
];

// Email domains that are typically benign
const legitEmailDomains = [
  /\b(gmail|outlook|hotmail|yahoo|aol|icloud|protonmail)\.com\b/i,
  /\b(microsoft|google|apple|amazon)\.com\b/i,
  /\b[\w.-]+@[\w.-]+\.(edu|gov|mil)\b/i, // Educational/government
];

const isLegitimateWebsiteUrl = (url: string): boolean => {
  return legitWebsitePatterns.some(pattern => pattern.test(url)) ||
         benignUrlPaths.some(pattern => pattern.test(url));
};

const isLegitimateEmail = (email: string): boolean => {
  return legitEmailDomains.some(pattern => pattern.test(email));
};

const isLegitimateWebsiteDomain = (domain: string): boolean => {
  return legitWebsitePatterns.some(pattern => pattern.test(domain));
};

// RFC1918 and ULA ranges to exclude
const privateRanges = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^169\.254\./, // Link-local
  /^127\./, // Loopback
  /^fe80:/i, // IPv6 link-local
  /^fc00:/i, // IPv6 ULA
  /^fd00:/i  // IPv6 ULA
];

const isPrivateIP = (ip: string): boolean => {
  return privateRanges.some(range => range.test(ip));
};

// AI-powered content analysis for IOC filtering
const analyzeContentWithAI = async (text: string, iocs: IOCSet): Promise<IOCSet> => {
  try {
    // Dynamic import to avoid circular dependency
    const { llmService } = await import('./llm-service');
    const { URLScanner } = await import('./url-scanner');

    const hasConfiguredProviders = await llmService.hasConfiguredProviders();
    if (!hasConfiguredProviders) {
      console.log('No AI providers configured, skipping AI-powered IOC filtering');
      return iocs;
    }

    // Prepare IOC summary for AI analysis
    const iocSummary = [
      `IPs: ${iocs.ipv4.concat(iocs.ipv6).slice(0, 10).join(', ')}${iocs.ipv4.length + iocs.ipv6.length > 10 ? '...' : ''}`,
      `Domains: ${iocs.domains.slice(0, 10).join(', ')}${iocs.domains.length > 10 ? '...' : ''}`,
      `URLs: ${iocs.urls.slice(0, 5).join(', ')}${iocs.urls.length > 5 ? '...' : ''}`,
      `Hashes: ${iocs.sha256.concat(iocs.md5).slice(0, 5).join(', ')}${iocs.sha256.length + iocs.md5.length > 5 ? '...' : ''}`,
      `Emails: ${iocs.emails.slice(0, 5).join(', ')}${iocs.emails.length > 5 ? '...' : ''}`
    ].filter(line => !line.includes(': ') || line.split(': ')[1].trim().length > 0);

    const response = await llmService.generateCQL({
      systemPrompt: `You are a cybersecurity expert analyzing IOCs (Indicators of Compromise) extracted from threat intelligence content. Your task is to identify which IOCs are likely related to actual threats vs. benign website infrastructure.

IMPORTANT: Respond with ONLY a JSON object containing arrays of IOCs to KEEP (threat-related). Do not include explanations or other text.

Consider these factors:
- Threat-related: C2 servers, malware hosting, phishing sites, suspicious domains, attacker infrastructure
- Benign: CDNs, legitimate services, social media, news sites, analytics, website resources, navigation links
- Context: Look for threat indicators like "malicious", "C2", "payload", "exploit", "phishing" in the source text
- Domain reputation: Well-known legitimate services should be filtered out
- URL patterns: Resource files (.js, .css, .png), admin panels, login pages are usually benign`,
      userPrompt: `Analyze this threat intelligence content and the extracted IOCs. Return only the IOCs that appear to be threat-related.

Content excerpt (first 1000 chars):
${text.substring(0, 1000)}

Extracted IOCs:
${iocSummary.join('\n')}

Return JSON format:
{
  "ipv4": ["threat_ip1", "threat_ip2"],
  "ipv6": ["threat_ipv6_1"],
  "domains": ["malicious.domain", "c2.server"],
  "urls": ["http://malicious.url"],
  "sha256": ["hash1", "hash2"],
  "md5": ["hash1"],
  "emails": ["attacker@email"]
}`,
      preferredModel: 'claude-3-haiku-20240307',
      maxTokens: 2000,
      temperature: 0.1
    });

    // Parse AI response
    const aiResponse = response.content.trim();
    let aiFilteredIOCs: IOCSet;
    
    try {
      // Try to extract JSON from response
      const jsonMatch = aiResponse.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        aiFilteredIOCs = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('No JSON found in response');
      }
    } catch (parseError) {
      console.warn('Failed to parse AI response, using original IOCs:', parseError);
      return iocs;
    }

    // Validate and merge AI results with original IOCs
    const filteredIOCs: IOCSet = {
      ipv4: iocs.ipv4.filter(ip => aiFilteredIOCs.ipv4?.includes(ip)),
      ipv6: iocs.ipv6.filter(ip => aiFilteredIOCs.ipv6?.includes(ip)),
      domains: iocs.domains.filter(domain => aiFilteredIOCs.domains?.includes(domain)),
      urls: iocs.urls.filter(url => aiFilteredIOCs.urls?.includes(url)),
      sha256: iocs.sha256.filter(hash => aiFilteredIOCs.sha256?.includes(hash)),
      md5: iocs.md5.filter(hash => aiFilteredIOCs.md5?.includes(hash)),
      emails: iocs.emails.filter(email => aiFilteredIOCs.emails?.includes(email))
    };

    console.log(`AI filtering: ${getIOCCounts(iocs).total} -> ${getIOCCounts(filteredIOCs).total} IOCs`);
    return filteredIOCs;

  } catch (error) {
    console.warn('AI-powered IOC filtering failed, using original IOCs:', error);
    return iocs;
  }
};

export const extractIOCs = (text: string, includePrivate = false, filterLegitimate = true, sourceUrl?: string, useAI = false, onProgress?: (progress: { processed: number; total: number }) => void, useBatchProcessing = false): IOCSet => {
  // Normalize common defanged formats (hxxp, [.] etc.) to improve extraction
  const normalizeText = (t: string) => {
    let s = t;
    // Normalize hxxp/hxxps
    s = s.replace(/hxxp(s?):\/\//gi, 'http$1://');
    // Normalize defanged dots
    s = s.replace(/\[\.\]/g, '.'); // [.] -> .
    s = s.replace(/\(dot\)/gi, '.'); // (dot) -> .
    s = s.replace(/\[dot\]/gi, '.'); // [dot] -> .
    s = s.replace(/(\(|\{|\[)\.(\)|\}|\])/g, '.'); // (.) / {.} / [.] -> .
    // Remove zero-width chars
    s = s.replace(/[\u200B-\u200D\uFEFF]/g, '');
    return s;
  };

  const source = normalizeText(text);

  const iocs: IOCSet = {
    ipv4: [],
    ipv6: [],
    domains: [],
    urls: [],
    sha256: [],
    md5: [],
    emails: []
  };

  // Extract and normalize each IOC type
  const extractAndNormalize = (pattern: RegExp, type: keyof IOCSet, normalizer?: (s: string) => string) => {
    const matches = source.match(pattern) || [];
    const normalized = matches.map(match => (normalizer ? normalizer(match) : match).trim());
    const unique = [...new Set(normalized)];
    
    if (type === 'ipv4' && !includePrivate) {
      return unique.filter(ip => !isPrivateIP(ip));
    }
    
    return unique;
  };

  iocs.ipv4 = extractAndNormalize(patterns.ipv4, 'ipv4');
  iocs.ipv6 = extractAndNormalize(patterns.ipv6, 'ipv6', (ip) => ip.toLowerCase());
  iocs.sha256 = extractAndNormalize(patterns.sha256, 'sha256', (hash) => hash.toLowerCase());
  iocs.md5 = extractAndNormalize(patterns.md5, 'md5', (hash) => hash.toLowerCase());
  
  // Extract URLs with filtering
  const allUrls = extractAndNormalize(patterns.url, 'urls', (url) => url.toLowerCase());
  let filteredUrls = filterLegitimate 
    ? allUrls.filter(url => !isLegitimateWebsiteUrl(url))
    : allUrls;
  
  // Filter out source URL domain if provided
  if (sourceUrl && filterLegitimate) {
    try {
      const sourceDomain = new URL(sourceUrl).hostname.toLowerCase();
      filteredUrls = filteredUrls.filter(url => {
        try {
          return new URL(url).hostname.toLowerCase() !== sourceDomain;
        } catch {
          return true;
        }
      });
    } catch {
      // Invalid source URL, continue without filtering
    }
  }
  
  iocs.urls = filteredUrls;
  
  // Extract email addresses with filtering
  const allEmails = extractAndNormalize(patterns.email, 'emails', (email) => email.toLowerCase());
  iocs.emails = filterLegitimate
    ? allEmails.filter(email => !isLegitimateEmail(email))
    : allEmails;
  
  // Extract domains, excluding those from URLs and filtering out legitimate ones
  const urlDomains = new Set(iocs.urls.map(url => {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }).filter(Boolean));
  
  const allDomains = extractAndNormalize(patterns.domain, 'domains', (domain) => domain.toLowerCase());
  let filteredDomains = allDomains.filter(domain => !urlDomains.has(domain));
  
  if (filterLegitimate) {
    filteredDomains = filteredDomains.filter(domain => !isLegitimateWebsiteDomain(domain));
  }
  
  // Filter out source domain if provided
  if (sourceUrl && filterLegitimate) {
    try {
      const sourceDomain = new URL(sourceUrl).hostname.toLowerCase();
      filteredDomains = filteredDomains.filter(domain => domain !== sourceDomain);
    } catch {
      // Invalid source URL, continue without filtering
    }
  }
  
  iocs.domains = filteredDomains;

  return iocs;
};

// Enhanced IOC extraction with AI-powered filtering
export const extractIOCsWithAI = async (text: string, includePrivate = false, filterLegitimate = true, sourceUrl?: string): Promise<IOCSet> => {
  // First extract IOCs using traditional methods
  const initialIOCs = extractIOCs(text, includePrivate, filterLegitimate, sourceUrl, false);
  
  // Then apply AI-powered filtering if IOCs were found
  if (getIOCCounts(initialIOCs).total > 0) {
    return await analyzeContentWithAI(text, initialIOCs);
  }
  
  return initialIOCs;
};

// Batch processing for large IOC extraction
export const extractIOCsWithBatching = async (
  text: string,
  includePrivate: boolean = false,
  filterLegitimate: boolean = true,
  onProgress?: (progress: any) => void
): Promise<IOCSet> => {
  const textLength = text.length;
  
  // Use batch processing for large texts (>100KB)
  if (textLength > 100000) {
    // Dynamic import to avoid circular dependency
    const { batchProcessor } = await import('./batch-processor');
    
    const result = await batchProcessor.processIOCsInBatches(
      text,
      (chunk: string) => extractIOCs(chunk, includePrivate, filterLegitimate),
      {
        batchSize: 50, // Process 50 lines at a time
        maxConcurrency: 3,
        delayBetweenBatches: 50,
        enableProgressTracking: true
      }
    );
    
    if (onProgress) {
      onProgress(result);
    }
    
    return batchProcessor.mergeIOCResults(result.results);
  } else {
    // Use regular extraction for smaller texts
    return extractIOCs(text, includePrivate, filterLegitimate);
  }
};

export const getIOCCounts = (iocs: IOCSet): IOCCounts => {
  const counts = {
    ipv4: iocs.ipv4.length,
    ipv6: iocs.ipv6.length,
    domains: iocs.domains.length,
    urls: iocs.urls.length,
    sha256: iocs.sha256.length,
    md5: iocs.md5.length,
    emails: iocs.emails.length,
    total: 0
  };
  
  counts.total = Object.values(counts).reduce((sum, count) => sum + count, 0) - counts.total;
  return counts;
};

export const formatIOCsForTemplate = (iocs: string[]): string => {
  return iocs.map(ioc => `"${ioc}"`).join(', ');
};