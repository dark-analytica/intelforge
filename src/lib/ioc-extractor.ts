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

// Common legitimate website patterns to filter out
const legitWebsitePatterns = [
  // Social media and common platforms
  /\b(facebook|twitter|linkedin|instagram|youtube|github|reddit)\.com\b/i,
  /\b(google|microsoft|apple|amazon|cloudflare)\.com\b/i,
  /\b(stackoverflow|wikipedia|w3\.org|mozilla\.org)\.com?\b/i,
  
  // Threat intel blogs and legitimate security content
  /\baka\.ms\b/i,
  /\bthecyberwire\.com\b/i,
  
  // CDNs and common services  
  /\b(unpkg|jsdelivr|cdnjs|googleapis|bootstrapcdn|jquery)\.com?\b/i,
  /\b(gravatar|disqus|addthis|shareaholic)\.com\b/i,
  
  // Common website infrastructure
  /\b(docs?\.|support\.|help\.|kb\.|faq\.|blog\.|news\.|www\.)[\w.-]+\.(com|org|net|edu|gov)\b/i,
  /\b[\w.-]+\.(png|jpg|jpeg|gif|webp|svg|ico|css|js|woff|ttf|pdf|mp4|avi|mp3)\b/i,
  
  // Analytics and tracking (legitimate)
  /\b(analytics\.google|googletagmanager|doubleclick|adsystem\.google)\.com\b/i,
  /\b(google-analytics|gtag|ga\.js)\b/i,
];

// Common benign URL paths that are likely navigation/resources
const benignUrlPaths = [
  /\/(about|contact|privacy|terms|support|help|faq|blog|news)$/i,
  /\/(css|js|images?|assets?|static|media|fonts?)\//i,
  /\.(css|js|png|jpg|jpeg|gif|webp|svg|ico|woff|ttf|pdf|mp4|avi|mp3)(\?.*)?$/i,
  /\/wp-(content|includes|admin)\//i,
  /\/(node_modules|bower_components)\//i,
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

export const extractIOCs = (text: string, includePrivate = false, filterLegitimate = true, sourceUrl?: string): IOCSet => {
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