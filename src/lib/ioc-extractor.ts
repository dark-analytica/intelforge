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

export const extractIOCs = (text: string, includePrivate = false): IOCSet => {
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
    const matches = text.match(pattern) || [];
    const normalized = matches.map(match => normalizer ? normalizer(match) : match);
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
  iocs.emails = extractAndNormalize(patterns.email, 'emails', (email) => email.toLowerCase());
  
  // Extract URLs first, then domains (excluding domains from URLs)
  iocs.urls = extractAndNormalize(patterns.url, 'urls', (url) => url.toLowerCase());
  const urlDomains = new Set(iocs.urls.map(url => {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }).filter(Boolean));
  
  const allDomains = extractAndNormalize(patterns.domain, 'domains', (domain) => domain.toLowerCase());
  iocs.domains = allDomains.filter(domain => !urlDomains.has(domain));

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