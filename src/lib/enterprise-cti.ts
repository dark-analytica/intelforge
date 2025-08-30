import { IOC, IOCType } from './ioc-extractor';
import { RateLimiter } from './rate-limiter';

export interface EnterpriseProvider {
  id: string;
  name: string;
  tier: 'enterprise' | 'premium' | 'government';
  apiEndpoint: string;
  authType: 'api_key' | 'oauth' | 'certificate';
  rateLimit: {
    requests: number;
    window: number; // seconds
  };
  supportedIOCs: IOCType[];
  features: string[];
}

export interface EnterpriseAPIConfig {
  providerId: string;
  apiKey?: string;
  clientId?: string;
  clientSecret?: string;
  certificatePath?: string;
  baseUrl?: string;
  customHeaders?: Record<string, string>;
}

export interface ThreatIntelligence {
  ioc: string;
  type: IOCType;
  provider: string;
  confidence: number; // 0-100
  severity: 'low' | 'medium' | 'high' | 'critical';
  reputation: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  firstSeen?: string;
  lastSeen?: string;
  tags: string[];
  attributes: {
    malwareFamily?: string[];
    threatActor?: string[];
    campaign?: string[];
    techniques?: string[];
    sectors?: string[];
    countries?: string[];
  };
  context: {
    description?: string;
    references?: string[];
    relatedIOCs?: string[];
    killChain?: string[];
  };
  rawData?: any;
}

export interface ThreatCorrelation {
  primaryIOC: string;
  relatedThreats: ThreatIntelligence[];
  correlationScore: number;
  commonAttributes: string[];
  timeline: {
    date: string;
    event: string;
    source: string;
  }[];
  riskAssessment: {
    score: number; // 0-100
    factors: string[];
    recommendation: string;
  };
}

export interface ThreatFeed {
  providerId: string;
  feedType: 'indicators' | 'reports' | 'signatures' | 'rules';
  lastUpdate: string;
  totalRecords: number;
  indicators: ThreatIntelligence[];
  metadata: {
    version: string;
    format: string;
    classification?: string;
    tlp?: 'white' | 'green' | 'amber' | 'red';
  };
}

class EnterpriseCTIService {
  private providers: Map<string, EnterpriseProvider> = new Map();
  private configs: Map<string, EnterpriseAPIConfig> = new Map();
  private rateLimiters: Map<string, RateLimiter> = new Map();
  private cache: Map<string, { data: any; timestamp: number; ttl: number }> = new Map();

  constructor() {
    this.initializeProviders();
  }

  private initializeProviders() {
    // Recorded Future
    this.providers.set('recordedfuture', {
      id: 'recordedfuture',
      name: 'Recorded Future',
      tier: 'enterprise',
      apiEndpoint: 'https://api.recordedfuture.com/v2',
      authType: 'api_key',
      rateLimit: { requests: 1000, window: 3600 },
      supportedIOCs: ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'md5', 'sha1'],
      features: ['threat_intelligence', 'risk_scoring', 'attribution', 'timeline', 'context']
    });

    // CrowdStrike Falcon X
    this.providers.set('crowdstrike_falcon', {
      id: 'crowdstrike_falcon',
      name: 'CrowdStrike Falcon X Intelligence',
      tier: 'enterprise',
      apiEndpoint: 'https://api.crowdstrike.com',
      authType: 'oauth',
      rateLimit: { requests: 5000, window: 3600 },
      supportedIOCs: ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'md5', 'sha1', 'email'],
      features: ['threat_intelligence', 'actor_attribution', 'malware_analysis', 'indicators']
    });

    // Google Threat Intelligence (formerly Mandiant)
    this.providers.set('google_threat_intel', {
      id: 'google_threat_intel',
      name: 'Google Threat Intelligence',
      tier: 'enterprise',
      apiEndpoint: 'https://www.virustotal.com/api/v3',
      authType: 'api_key',
      rateLimit: { requests: 2000, window: 3600 },
      supportedIOCs: ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'md5', 'sha1'],
      features: ['threat_intelligence', 'malware_families', 'campaigns', 'vulnerabilities', 'mandiant_reports']
    });

    // VirusTotal Enterprise
    this.providers.set('virustotal_enterprise', {
      id: 'virustotal_enterprise',
      name: 'VirusTotal Enterprise',
      tier: 'enterprise',
      apiEndpoint: 'https://www.virustotal.com/api/v3',
      authType: 'api_key',
      rateLimit: { requests: 10000, window: 3600 },
      supportedIOCs: ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'md5', 'sha1'],
      features: ['threat_intelligence', 'hunting', 'graph_analysis', 'private_scanning', 'feeds']
    });

    // Proofpoint TAP
    this.providers.set('proofpoint', {
      id: 'proofpoint',
      name: 'Proofpoint Targeted Attack Protection',
      tier: 'enterprise',
      apiEndpoint: 'https://tap-api-v2.proofpoint.com',
      authType: 'api_key',
      rateLimit: { requests: 3000, window: 3600 },
      supportedIOCs: ['url', 'domain', 'sha256', 'email'],
      features: ['email_threats', 'url_analysis', 'attachment_analysis', 'campaign_tracking']
    });

    // ThreatConnect
    this.providers.set('threatconnect', {
      id: 'threatconnect',
      name: 'ThreatConnect',
      tier: 'enterprise',
      apiEndpoint: 'https://api.threatconnect.com',
      authType: 'api_key',
      rateLimit: { requests: 2500, window: 3600 },
      supportedIOCs: ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'md5', 'sha1', 'email'],
      features: ['threat_intelligence', 'playbooks', 'analytics', 'collaboration']
    });

    // Government/Sector Feeds
    this.providers.set('cisa', {
      id: 'cisa',
      name: 'CISA Cybersecurity Advisories',
      tier: 'government',
      apiEndpoint: 'https://www.cisa.gov/api',
      authType: 'api_key',
      rateLimit: { requests: 500, window: 3600 },
      supportedIOCs: ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'md5'],
      features: ['advisories', 'vulnerabilities', 'indicators', 'alerts']
    });

    // Initialize rate limiters
    this.providers.forEach(provider => {
      this.rateLimiters.set(provider.id, new RateLimiter(
        provider.rateLimit.requests,
        provider.rateLimit.window * 1000
      ));
    });
  }

  configureProvider(config: EnterpriseAPIConfig): void {
    if (!this.providers.has(config.providerId)) {
      throw new Error(`Unknown provider: ${config.providerId}`);
    }

    this.configs.set(config.providerId, config);
  }

  async enrichIOC(ioc: string, type: IOCType, providers?: string[]): Promise<ThreatIntelligence[]> {
    const targetProviders = providers || Array.from(this.providers.keys());
    const results: ThreatIntelligence[] = [];

    for (const providerId of targetProviders) {
      const provider = this.providers.get(providerId);
      const config = this.configs.get(providerId);

      if (!provider || !config) {
        console.warn(`Provider ${providerId} not configured, skipping`);
        continue;
      }

      if (!provider.supportedIOCs.includes(type)) {
        continue;
      }

      try {
        const intelligence = await this.queryProvider(providerId, ioc, type);
        if (intelligence) {
          results.push(intelligence);
        }
      } catch (error) {
        console.error(`Error querying ${providerId}:`, error);
      }
    }

    return results;
  }

  async correlateThreat(ioc: string, type: IOCType): Promise<ThreatCorrelation> {
    const intelligence = await this.enrichIOC(ioc, type);
    
    // Analyze correlations across providers
    const relatedIOCs = new Set<string>();
    const commonActors = new Set<string>();
    const commonCampaigns = new Set<string>();
    const commonMalware = new Set<string>();

    intelligence.forEach(intel => {
      intel.context.relatedIOCs?.forEach(related => relatedIOCs.add(related));
      intel.attributes.threatActor?.forEach(actor => commonActors.add(actor));
      intel.attributes.campaign?.forEach(campaign => commonCampaigns.add(campaign));
      intel.attributes.malwareFamily?.forEach(malware => commonMalware.add(malware));
    });

    // Calculate correlation score
    const correlationScore = this.calculateCorrelationScore(intelligence);

    // Generate timeline
    const timeline = this.generateTimeline(intelligence);

    // Risk assessment
    const riskAssessment = this.assessRisk(intelligence, correlationScore);

    return {
      primaryIOC: ioc,
      relatedThreats: intelligence,
      correlationScore,
      commonAttributes: [
        ...Array.from(commonActors),
        ...Array.from(commonCampaigns),
        ...Array.from(commonMalware)
      ],
      timeline,
      riskAssessment
    };
  }

  async ingestThreatFeed(providerId: string, feedType: ThreatFeed['feedType']): Promise<ThreatFeed> {
    const provider = this.providers.get(providerId);
    const config = this.configs.get(providerId);

    if (!provider || !config) {
      throw new Error(`Provider ${providerId} not configured`);
    }

    const rateLimiter = this.rateLimiters.get(providerId)!;
    await rateLimiter.waitForToken();

    try {
      const feedData = await this.fetchThreatFeed(providerId, feedType);
      
      const feed: ThreatFeed = {
        providerId,
        feedType,
        lastUpdate: new Date().toISOString(),
        totalRecords: feedData.indicators?.length || 0,
        indicators: feedData.indicators || [],
        metadata: {
          version: feedData.version || '1.0',
          format: feedData.format || 'json',
          classification: feedData.classification,
          tlp: feedData.tlp || 'green'
        }
      };

      // Cache the feed
      this.cacheData(`feed_${providerId}_${feedType}`, feed, 3600000); // 1 hour TTL

      return feed;
    } catch (error) {
      console.error(`Error ingesting feed from ${providerId}:`, error);
      throw error;
    }
  }

  private async queryProvider(providerId: string, ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    const cacheKey = `${providerId}_${ioc}_${type}`;
    const cached = this.getCachedData(cacheKey);
    if (cached) {
      return cached;
    }

    const rateLimiter = this.rateLimiters.get(providerId)!;
    await rateLimiter.waitForToken();

    let intelligence: ThreatIntelligence | null = null;

    switch (providerId) {
      case 'recordedfuture':
        intelligence = await this.queryRecordedFuture(ioc, type);
        break;
      case 'crowdstrike_falcon':
        intelligence = await this.queryCrowdStrikeFalcon(ioc, type);
        break;
      case 'mandiant':
        intelligence = await this.queryMandiant(ioc, type);
        break;
      case 'fireeye':
        intelligence = await this.queryFireEye(ioc, type);
        break;
      case 'proofpoint':
        intelligence = await this.queryProofpoint(ioc, type);
        break;
      case 'threatconnect':
        intelligence = await this.queryThreatConnect(ioc, type);
        break;
      case 'cisa':
        intelligence = await this.queryCISA(ioc, type);
        break;
      default:
        throw new Error(`Unsupported provider: ${providerId}`);
    }

    if (intelligence) {
      this.cacheData(cacheKey, intelligence, 1800000); // 30 minutes TTL
    }

    return intelligence;
  }

  private async queryRecordedFuture(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    const config = this.configs.get('recordedfuture')!;
    const endpoint = `${this.providers.get('recordedfuture')!.apiEndpoint}/intelligence/lookup`;

    const response = await fetch(`${endpoint}?entity=${ioc}&type=${type}`, {
      headers: {
        'X-RFToken': config.apiKey!,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Recorded Future API error: ${response.statusText}`);
    }

    const data = await response.json();
    
    return {
      ioc,
      type,
      provider: 'recordedfuture',
      confidence: data.risk?.score || 0,
      severity: this.mapRiskToSeverity(data.risk?.score || 0),
      reputation: data.risk?.level || 'unknown',
      firstSeen: data.timestamps?.first,
      lastSeen: data.timestamps?.last,
      tags: data.tags || [],
      attributes: {
        malwareFamily: data.malware || [],
        threatActor: data.actors || [],
        campaign: data.campaigns || [],
        techniques: data.techniques || []
      },
      context: {
        description: data.description,
        references: data.references || [],
        relatedIOCs: data.related || []
      },
      rawData: data
    };
  }

  private async queryCrowdStrikeFalcon(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    const config = this.configs.get('crowdstrike_falcon')!;
    
    // First get OAuth token
    const tokenResponse = await fetch('https://api.crowdstrike.com/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `client_id=${config.clientId}&client_secret=${config.clientSecret}&grant_type=client_credentials`
    });

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Query intelligence
    const response = await fetch(`https://api.crowdstrike.com/intel/entities/indicators/v1?type=${type}&value=${ioc}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`CrowdStrike API error: ${response.statusText}`);
    }

    const data = await response.json();
    const indicator = data.resources?.[0];

    if (!indicator) {
      return null;
    }

    return {
      ioc,
      type,
      provider: 'crowdstrike_falcon',
      confidence: indicator.confidence || 0,
      severity: indicator.severity || 'low',
      reputation: indicator.malicious_confidence || 'unknown',
      firstSeen: indicator.published_date,
      lastSeen: indicator.last_updated,
      tags: indicator.labels || [],
      attributes: {
        malwareFamily: indicator.malware_families || [],
        threatActor: indicator.actors || [],
        campaign: indicator.campaigns || []
      },
      context: {
        description: indicator.description,
        references: indicator.reports || [],
        killChain: indicator.kill_chains || []
      },
      rawData: indicator
    };
  }

  private async queryMandiant(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    // Placeholder implementation - would need actual Mandiant API integration
    return null;
  }

  private async queryFireEye(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    // Placeholder implementation - would need actual FireEye API integration
    return null;
  }

  private async queryProofpoint(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    // Placeholder implementation - would need actual Proofpoint API integration
    return null;
  }

  private async queryThreatConnect(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    // Placeholder implementation - would need actual ThreatConnect API integration
    return null;
  }

  private async queryCISA(ioc: string, type: IOCType): Promise<ThreatIntelligence | null> {
    // Placeholder implementation - would need actual CISA API integration
    return null;
  }

  private async fetchThreatFeed(providerId: string, feedType: string): Promise<any> {
    // Placeholder implementation for feed ingestion
    return {
      indicators: [],
      version: '1.0',
      format: 'json'
    };
  }

  private calculateCorrelationScore(intelligence: ThreatIntelligence[]): number {
    if (intelligence.length === 0) return 0;

    let score = 0;
    const weights = {
      confidence: 0.3,
      providerCount: 0.2,
      attributeOverlap: 0.3,
      timelineConsistency: 0.2
    };

    // Average confidence
    const avgConfidence = intelligence.reduce((sum, intel) => sum + intel.confidence, 0) / intelligence.length;
    score += (avgConfidence / 100) * weights.confidence;

    // Provider diversity
    const uniqueProviders = new Set(intelligence.map(intel => intel.provider)).size;
    score += Math.min(uniqueProviders / 3, 1) * weights.providerCount;

    // Attribute overlap
    const allActors = intelligence.flatMap(intel => intel.attributes.threatActor || []);
    const allCampaigns = intelligence.flatMap(intel => intel.attributes.campaign || []);
    const actorOverlap = new Set(allActors).size < allActors.length ? 0.5 : 0;
    const campaignOverlap = new Set(allCampaigns).size < allCampaigns.length ? 0.5 : 0;
    score += (actorOverlap + campaignOverlap) * weights.attributeOverlap;

    return Math.min(score * 100, 100);
  }

  private generateTimeline(intelligence: ThreatIntelligence[]): ThreatCorrelation['timeline'] {
    const events: ThreatCorrelation['timeline'] = [];

    intelligence.forEach(intel => {
      if (intel.firstSeen) {
        events.push({
          date: intel.firstSeen,
          event: `First observed by ${intel.provider}`,
          source: intel.provider
        });
      }
      if (intel.lastSeen && intel.lastSeen !== intel.firstSeen) {
        events.push({
          date: intel.lastSeen,
          event: `Last observed by ${intel.provider}`,
          source: intel.provider
        });
      }
    });

    return events.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  }

  private assessRisk(intelligence: ThreatIntelligence[], correlationScore: number): ThreatCorrelation['riskAssessment'] {
    const avgConfidence = intelligence.reduce((sum, intel) => sum + intel.confidence, 0) / intelligence.length;
    const highSeverityCount = intelligence.filter(intel => intel.severity === 'high' || intel.severity === 'critical').length;
    
    let riskScore = avgConfidence * 0.4 + correlationScore * 0.3 + (highSeverityCount / intelligence.length) * 30;
    riskScore = Math.min(riskScore, 100);

    const factors = [];
    if (avgConfidence > 80) factors.push('High confidence from multiple sources');
    if (correlationScore > 70) factors.push('Strong correlation across providers');
    if (highSeverityCount > 0) factors.push('High severity indicators present');

    let recommendation = 'Monitor for suspicious activity';
    if (riskScore > 80) recommendation = 'Immediate investigation and blocking recommended';
    else if (riskScore > 60) recommendation = 'Enhanced monitoring and analysis recommended';
    else if (riskScore > 40) recommendation = 'Standard monitoring sufficient';

    return {
      score: Math.round(riskScore),
      factors,
      recommendation
    };
  }

  private mapRiskToSeverity(score: number): ThreatIntelligence['severity'] {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  private cacheData(key: string, data: any, ttl: number): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    });
  }

  private getCachedData(key: string): any | null {
    const cached = this.cache.get(key);
    if (!cached) return null;

    if (Date.now() - cached.timestamp > cached.ttl) {
      this.cache.delete(key);
      return null;
    }

    return cached.data;
  }

  getProviders(): EnterpriseProvider[] {
    return Array.from(this.providers.values());
  }

  getConfiguredProviders(): string[] {
    return Array.from(this.configs.keys());
  }
}

export const enterpriseCTI = new EnterpriseCTIService();
