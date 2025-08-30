import { IOCSet, IOCType } from './ioc-extractor';

export interface CTIProvider {
  id: string;
  name: string;
  description: string;
  apiUrl: string;
  rateLimits: {
    requestsPerMinute: number;
    requestsPerDay: number;
  };
  supportedIOCTypes: IOCType[];
  enrichmentFields: string[];
  requiresApiKey: boolean;
  tier: 'free' | 'freemium' | 'enterprise';
}

export interface CTIEnrichmentResult {
  ioc: string;
  type: IOCType;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  confidence: number;
  sources: string[];
  metadata: Record<string, any>;
  lastUpdated: Date;
  provider: string;
}

export interface CTIEnrichmentRequest {
  iocs: IOCSet;
  providers?: string[];
  maxAge?: number; // Cache age in hours
  priority?: 'high' | 'medium' | 'low';
}

// CTI Provider configurations
export const ctiProviders: CTIProvider[] = [
  // Tier 1: Free/Public APIs
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    description: 'IP address reputation and abuse reporting',
    apiUrl: 'https://api.abuseipdb.com/api/v2',
    rateLimits: {
      requestsPerMinute: 60,
      requestsPerDay: 5000
    },
    supportedIOCTypes: ['ipv4', 'ipv6'],
    enrichmentFields: ['abuse_confidence', 'country_code', 'usage_type', 'isp'],
    requiresApiKey: true,
    tier: 'free'
  },
  {
    id: 'urlhaus',
    name: 'URLhaus',
    description: 'Malicious URL database by abuse.ch',
    apiUrl: 'https://urlhaus-api.abuse.ch/v1',
    rateLimits: {
      requestsPerMinute: 100,
      requestsPerDay: 10000
    },
    supportedIOCTypes: ['urls', 'domains'],
    enrichmentFields: ['threat_type', 'malware_family', 'first_seen', 'last_seen'],
    requiresApiKey: false,
    tier: 'free'
  },
  {
    id: 'threatfox',
    name: 'ThreatFox',
    description: 'IOC database by abuse.ch',
    apiUrl: 'https://threatfox-api.abuse.ch/api/v1',
    rateLimits: {
      requestsPerMinute: 100,
      requestsPerDay: 10000
    },
    supportedIOCTypes: ['ipv4', 'ipv6', 'domains', 'urls', 'sha256', 'md5'],
    enrichmentFields: ['malware_family', 'threat_type', 'confidence_level', 'first_seen'],
    requiresApiKey: false,
    tier: 'free'
  },
  {
    id: 'otx',
    name: 'AlienVault OTX',
    description: 'Open Threat Exchange community intelligence',
    apiUrl: 'https://otx.alienvault.com/api/v1',
    rateLimits: {
      requestsPerMinute: 167,
      requestsPerDay: 10000
    },
    supportedIOCTypes: ['ipv4', 'ipv6', 'domains', 'urls', 'sha256', 'md5', 'emails'],
    enrichmentFields: ['pulse_count', 'malware_families', 'attack_ids', 'country'],
    requiresApiKey: true,
    tier: 'free'
  },
  
  // Tier 2: Freemium APIs
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: 'Multi-engine malware analysis service',
    apiUrl: 'https://www.virustotal.com/vtapi/v2',
    rateLimits: {
      requestsPerMinute: 4,
      requestsPerDay: 1000
    },
    supportedIOCTypes: ['ipv4', 'ipv6', 'domains', 'urls', 'sha256', 'md5'],
    enrichmentFields: ['detection_ratio', 'scan_date', 'positives', 'total_scans'],
    requiresApiKey: true,
    tier: 'freemium'
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    description: 'Internet background noise intelligence',
    apiUrl: 'https://api.greynoise.io/v3',
    rateLimits: {
      requestsPerMinute: 10,
      requestsPerDay: 100
    },
    supportedIOCTypes: ['ipv4'],
    enrichmentFields: ['classification', 'noise', 'riot', 'first_seen', 'last_seen'],
    requiresApiKey: true,
    tier: 'freemium'
  }
];

class CTIService {
  private cache: Map<string, CTIEnrichmentResult> = new Map();
  private rateLimiters: Map<string, { requests: number; resetTime: number }> = new Map();

  async enrichIOCs(request: CTIEnrichmentRequest): Promise<CTIEnrichmentResult[]> {
    const results: CTIEnrichmentResult[] = [];
    const providers = request.providers || ctiProviders.map(p => p.id);
    
    // Process each IOC type
    for (const [type, iocList] of Object.entries(request.iocs)) {
      if (iocList.length === 0) continue;
      
      for (const ioc of iocList) {
        // Check cache first
        const cacheKey = `${ioc}-${providers.join(',')}`;
        const cached = this.getCachedResult(cacheKey, request.maxAge || 24);
        
        if (cached) {
          results.push(cached);
          continue;
        }
        
        // Enrich with available providers
        for (const providerId of providers) {
          const provider = ctiProviders.find(p => p.id === providerId);
          if (!provider || !provider.supportedIOCTypes.includes(type as IOCType)) {
            continue;
          }
          
          try {
            const enrichmentResult = await this.queryProvider(provider, ioc, type as IOCType);
            if (enrichmentResult) {
              results.push(enrichmentResult);
              this.cacheResult(cacheKey, enrichmentResult);
            }
          } catch (error) {
            console.warn(`CTI enrichment failed for ${provider.name}:`, error);
          }
        }
      }
    }
    
    return this.aggregateResults(results);
  }

  private async queryProvider(provider: CTIProvider, ioc: string, type: IOCType): Promise<CTIEnrichmentResult | null> {
    // Check rate limits
    if (!this.checkRateLimit(provider.id)) {
      console.warn(`Rate limit exceeded for ${provider.name}`);
      return null;
    }
    
    // Get API configuration
    const apiKey = await this.getApiKey(provider.id);
    if (provider.requiresApiKey && !apiKey) {
      console.warn(`API key required for ${provider.name}`);
      return null;
    }
    
    // Provider-specific query logic
    switch (provider.id) {
      case 'abuseipdb':
        return this.queryAbuseIPDB(ioc, apiKey);
      case 'urlhaus':
        return this.queryURLhaus(ioc, type);
      case 'threatfox':
        return this.queryThreatFox(ioc, type);
      case 'otx':
        return this.queryOTX(ioc, type, apiKey);
      case 'virustotal':
        return this.queryVirusTotal(ioc, type, apiKey);
      case 'greynoise':
        return this.queryGreyNoise(ioc, apiKey);
      default:
        return null;
    }
  }

  private async queryAbuseIPDB(ip: string, apiKey: string): Promise<CTIEnrichmentResult | null> {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    return {
      ioc: ip,
      type: 'ipv4',
      reputation: data.abuseConfidencePercentage > 75 ? 'malicious' : 
                 data.abuseConfidencePercentage > 25 ? 'suspicious' : 'clean',
      confidence: data.abuseConfidencePercentage,
      sources: ['AbuseIPDB'],
      metadata: {
        country_code: data.countryCode,
        usage_type: data.usageType,
        isp: data.isp,
        total_reports: data.totalReports
      },
      lastUpdated: new Date(),
      provider: 'abuseipdb'
    };
  }

  private async queryURLhaus(ioc: string, type: IOCType): Promise<CTIEnrichmentResult | null> {
    const endpoint = type === 'urls' ? 'url' : 'host';
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `${endpoint}=${encodeURIComponent(ioc)}`
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    if (data.query_status !== 'ok') return null;
    
    return {
      ioc,
      type,
      reputation: data.threat ? 'malicious' : 'unknown',
      confidence: data.threat ? 90 : 0,
      sources: ['URLhaus'],
      metadata: {
        threat_type: data.threat,
        malware_family: data.tags,
        first_seen: data.date_added,
        url_status: data.url_status
      },
      lastUpdated: new Date(),
      provider: 'urlhaus'
    };
  }

  private async queryThreatFox(ioc: string, type: IOCType): Promise<CTIEnrichmentResult | null> {
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: 'search_ioc',
        search_term: ioc
      })
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    if (data.query_status !== 'ok' || !data.data) return null;
    
    const result = data.data[0];
    return {
      ioc,
      type,
      reputation: 'malicious',
      confidence: result.confidence_level || 50,
      sources: ['ThreatFox'],
      metadata: {
        malware_family: result.malware,
        threat_type: result.threat_type,
        first_seen: result.first_seen,
        tags: result.tags
      },
      lastUpdated: new Date(),
      provider: 'threatfox'
    };
  }

  private async queryOTX(ioc: string, type: IOCType, apiKey: string): Promise<CTIEnrichmentResult | null> {
    const endpoint = this.getOTXEndpoint(type);
    if (!endpoint) return null;
    
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/${endpoint}/${ioc}/general`, {
      headers: { 'X-OTX-API-KEY': apiKey }
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    return {
      ioc,
      type,
      reputation: data.pulse_info?.count > 0 ? 'suspicious' : 'unknown',
      confidence: Math.min(data.pulse_info?.count * 10 || 0, 100),
      sources: ['AlienVault OTX'],
      metadata: {
        pulse_count: data.pulse_info?.count,
        malware_families: data.malware?.data?.map((m: any) => m.detections) || [],
        attack_ids: data.pulse_info?.pulses?.map((p: any) => p.attack_ids).flat() || []
      },
      lastUpdated: new Date(),
      provider: 'otx'
    };
  }

  private async queryVirusTotal(ioc: string, type: IOCType, apiKey: string): Promise<CTIEnrichmentResult | null> {
    const resource = type === 'ipv4' ? 'ip-address' : 
                   type === 'domains' ? 'domain' : 
                   type === 'urls' ? 'url' : 'file';
    
    const response = await fetch(`https://www.virustotal.com/vtapi/v2/${resource}/report?apikey=${apiKey}&resource=${ioc}`, {
      method: 'GET'
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    if (data.response_code !== 1) return null;
    
    const positives = data.positives || 0;
    const total = data.total || 1;
    const ratio = positives / total;
    
    return {
      ioc,
      type,
      reputation: ratio > 0.1 ? 'malicious' : ratio > 0.02 ? 'suspicious' : 'clean',
      confidence: Math.round(ratio * 100),
      sources: ['VirusTotal'],
      metadata: {
        detection_ratio: `${positives}/${total}`,
        scan_date: data.scan_date,
        permalink: data.permalink
      },
      lastUpdated: new Date(),
      provider: 'virustotal'
    };
  }

  private async queryGreyNoise(ip: string, apiKey: string): Promise<CTIEnrichmentResult | null> {
    const response = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
      headers: { 'key': apiKey }
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    return {
      ioc: ip,
      type: 'ipv4',
      reputation: data.noise ? 'suspicious' : data.riot ? 'clean' : 'unknown',
      confidence: data.noise ? 70 : data.riot ? 90 : 0,
      sources: ['GreyNoise'],
      metadata: {
        classification: data.classification,
        noise: data.noise,
        riot: data.riot,
        message: data.message
      },
      lastUpdated: new Date(),
      provider: 'greynoise'
    };
  }

  private getOTXEndpoint(type: IOCType): string | null {
    switch (type) {
      case 'ipv4':
      case 'ipv6':
        return 'IPv4';
      case 'domains':
        return 'domain';
      case 'urls':
        return 'url';
      case 'sha256':
      case 'md5':
        return 'file';
      default:
        return null;
    }
  }

  private checkRateLimit(providerId: string): boolean {
    const provider = ctiProviders.find(p => p.id === providerId);
    if (!provider) return false;
    
    const now = Date.now();
    const limiter = this.rateLimiters.get(providerId);
    
    if (!limiter || now > limiter.resetTime) {
      this.rateLimiters.set(providerId, {
        requests: 1,
        resetTime: now + 60000 // Reset every minute
      });
      return true;
    }
    
    if (limiter.requests >= provider.rateLimits.requestsPerMinute) {
      return false;
    }
    
    limiter.requests++;
    return true;
  }

  private async getApiKey(providerId: string): Promise<string | null> {
    // In a real implementation, this would retrieve from secure storage
    // For now, return null to indicate no API key available
    return null;
  }

  private getCachedResult(key: string, maxAgeHours: number): CTIEnrichmentResult | null {
    const cached = this.cache.get(key);
    if (!cached) return null;
    
    const ageHours = (Date.now() - cached.lastUpdated.getTime()) / (1000 * 60 * 60);
    return ageHours <= maxAgeHours ? cached : null;
  }

  private cacheResult(key: string, result: CTIEnrichmentResult): void {
    this.cache.set(key, result);
  }

  private aggregateResults(results: CTIEnrichmentResult[]): CTIEnrichmentResult[] {
    const grouped = new Map<string, CTIEnrichmentResult[]>();
    
    // Group results by IOC
    for (const result of results) {
      const key = result.ioc;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(result);
    }
    
    // Aggregate multiple results for the same IOC
    const aggregated: CTIEnrichmentResult[] = [];
    for (const [ioc, iocResults] of grouped) {
      if (iocResults.length === 1) {
        aggregated.push(iocResults[0]);
        continue;
      }
      
      // Combine multiple provider results
      const combined: CTIEnrichmentResult = {
        ioc,
        type: iocResults[0].type,
        reputation: this.aggregateReputation(iocResults),
        confidence: this.aggregateConfidence(iocResults),
        sources: [...new Set(iocResults.flatMap(r => r.sources))],
        metadata: this.aggregateMetadata(iocResults),
        lastUpdated: new Date(),
        provider: 'aggregated'
      };
      
      aggregated.push(combined);
    }
    
    return aggregated;
  }

  private aggregateReputation(results: CTIEnrichmentResult[]): 'malicious' | 'suspicious' | 'clean' | 'unknown' {
    const reputations = results.map(r => r.reputation);
    
    if (reputations.includes('malicious')) return 'malicious';
    if (reputations.includes('suspicious')) return 'suspicious';
    if (reputations.includes('clean')) return 'clean';
    return 'unknown';
  }

  private aggregateConfidence(results: CTIEnrichmentResult[]): number {
    const confidences = results.map(r => r.confidence);
    return Math.round(confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length);
  }

  private aggregateMetadata(results: CTIEnrichmentResult[]): Record<string, any> {
    const metadata: Record<string, any> = {};
    
    for (const result of results) {
      for (const [key, value] of Object.entries(result.metadata)) {
        if (!metadata[key]) {
          metadata[key] = value;
        } else if (Array.isArray(metadata[key])) {
          metadata[key] = [...new Set([...metadata[key], ...(Array.isArray(value) ? value : [value])])];
        }
      }
    }
    
    return metadata;
  }
}

export const ctiService = new CTIService();
