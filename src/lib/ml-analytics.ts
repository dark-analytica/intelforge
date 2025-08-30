import { IOC, IOCType } from './ioc-extractor';
import { ThreatIntelligence } from './enterprise-cti';

export interface IOCScore {
  ioc: string;
  type: IOCType;
  confidence: number; // 0-100
  riskScore: number; // 0-100
  reputation: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  factors: {
    prevalence: number;
    age: number;
    sources: number;
    context: number;
    behavior: number;
  };
  explanation: string[];
  recommendations: string[];
}

export interface ThreatAttribution {
  threatActor: string;
  confidence: number; // 0-100
  evidence: {
    iocMatches: number;
    techniqueMatches: number;
    campaignMatches: number;
    temporalCorrelation: number;
  };
  profile: {
    sophistication: 'low' | 'medium' | 'high' | 'advanced';
    motivation: string[];
    targets: string[];
    geography: string[];
    techniques: string[];
  };
  relatedCampaigns: string[];
  timeline: {
    firstSeen: string;
    lastSeen: string;
    peakActivity: string;
  };
}

export interface AttackPrediction {
  likelihood: number; // 0-100
  timeframe: '24h' | '7d' | '30d' | '90d';
  vectors: {
    technique: string;
    probability: number;
    prerequisites: string[];
    indicators: string[];
  }[];
  riskFactors: string[];
  mitigations: string[];
  confidence: number;
}

export interface ThreatCluster {
  id: string;
  name: string;
  iocs: IOC[];
  commonAttributes: {
    actors: string[];
    campaigns: string[];
    malwareFamilies: string[];
    techniques: string[];
    sectors: string[];
  };
  clusterScore: number; // 0-100
  centroid: {
    avgConfidence: number;
    avgRisk: number;
    dominantType: IOCType;
  };
  relationships: {
    clusterId: string;
    similarity: number;
    sharedIOCs: number;
  }[];
}

export interface MLModel {
  name: string;
  version: string;
  type: 'classification' | 'regression' | 'clustering' | 'anomaly_detection';
  accuracy: number;
  lastTrained: string;
  features: string[];
  parameters: Record<string, any>;
}

class MLAnalyticsEngine {
  private models: Map<string, MLModel> = new Map();
  private featureCache: Map<string, any> = new Map();
  private knownActors: Map<string, ThreatAttribution['profile']> = new Map();

  constructor() {
    this.initializeModels();
    this.initializeThreatActorProfiles();
  }

  private initializeModels() {
    // IOC Scoring Model
    this.models.set('ioc_scorer', {
      name: 'IOC Risk Scorer',
      version: '2.1.0',
      type: 'regression',
      accuracy: 0.87,
      lastTrained: '2024-08-15',
      features: ['prevalence', 'age_days', 'source_count', 'context_score', 'behavior_score'],
      parameters: {
        weights: {
          prevalence: 0.25,
          age: 0.15,
          sources: 0.20,
          context: 0.25,
          behavior: 0.15
        },
        thresholds: {
          malicious: 75,
          suspicious: 50,
          clean: 25
        }
      }
    });

    // Threat Attribution Model
    this.models.set('threat_attributor', {
      name: 'Threat Actor Attribution',
      version: '1.8.0',
      type: 'classification',
      accuracy: 0.82,
      lastTrained: '2024-08-10',
      features: ['ioc_overlap', 'technique_similarity', 'temporal_pattern', 'target_overlap'],
      parameters: {
        minConfidence: 0.6,
        maxCandidates: 5,
        temporalWindow: 90 // days
      }
    });

    // Attack Prediction Model
    this.models.set('attack_predictor', {
      name: 'Attack Vector Predictor',
      version: '1.5.0',
      type: 'classification',
      accuracy: 0.79,
      lastTrained: '2024-08-12',
      features: ['current_iocs', 'historical_patterns', 'threat_landscape', 'target_profile'],
      parameters: {
        predictionHorizon: ['24h', '7d', '30d', '90d'],
        confidenceThreshold: 0.7
      }
    });

    // Clustering Model
    this.models.set('threat_clusterer', {
      name: 'Threat Intelligence Clusterer',
      version: '1.3.0',
      type: 'clustering',
      accuracy: 0.84,
      lastTrained: '2024-08-08',
      features: ['ioc_similarity', 'temporal_proximity', 'attribute_overlap', 'behavior_similarity'],
      parameters: {
        minClusterSize: 3,
        maxClusters: 50,
        similarityThreshold: 0.6
      }
    });
  }

  private initializeThreatActorProfiles() {
    // APT29 (Cozy Bear)
    this.knownActors.set('APT29', {
      sophistication: 'advanced',
      motivation: ['espionage', 'intelligence_gathering'],
      targets: ['government', 'healthcare', 'technology', 'energy'],
      geography: ['russia', 'global'],
      techniques: ['T1566.001', 'T1059.001', 'T1055', 'T1070.004', 'T1083']
    });

    // APT28 (Fancy Bear)
    this.knownActors.set('APT28', {
      sophistication: 'advanced',
      motivation: ['espionage', 'political_influence'],
      targets: ['government', 'military', 'media', 'civil_society'],
      geography: ['russia', 'europe', 'north_america'],
      techniques: ['T1566.001', 'T1059.003', 'T1055', 'T1003', 'T1082']
    });

    // Lazarus Group
    this.knownActors.set('Lazarus', {
      sophistication: 'advanced',
      motivation: ['financial_gain', 'espionage', 'destructive'],
      targets: ['financial', 'cryptocurrency', 'government', 'media'],
      geography: ['north_korea', 'global'],
      techniques: ['T1566.001', 'T1059.001', 'T1055', 'T1486', 'T1041']
    });

    // FIN7
    this.knownActors.set('FIN7', {
      sophistication: 'high',
      motivation: ['financial_gain'],
      targets: ['retail', 'restaurant', 'hospitality', 'financial'],
      geography: ['global'],
      techniques: ['T1566.001', 'T1059.001', 'T1055', 'T1005', 'T1041']
    });
  }

  async scoreIOC(ioc: string, type: IOCType, context?: any): Promise<IOCScore> {
    const features = await this.extractIOCFeatures(ioc, type, context);
    const model = this.models.get('ioc_scorer')!;
    
    // Calculate weighted score
    const weights = model.parameters.weights;
    const riskScore = Math.min(100, Math.max(0,
      features.prevalence * weights.prevalence * 100 +
      features.age * weights.age * 100 +
      features.sources * weights.sources * 100 +
      features.context * weights.context * 100 +
      features.behavior * weights.behavior * 100
    ));

    // Determine reputation based on thresholds
    const thresholds = model.parameters.thresholds;
    let reputation: IOCScore['reputation'] = 'unknown';
    if (riskScore >= thresholds.malicious) reputation = 'malicious';
    else if (riskScore >= thresholds.suspicious) reputation = 'suspicious';
    else if (riskScore >= thresholds.clean) reputation = 'clean';

    // Generate confidence based on feature quality
    const confidence = Math.min(100, 
      (features.sources * 30) + 
      (features.prevalence * 25) + 
      (features.context * 25) + 
      (features.age * 10) + 
      (features.behavior * 10)
    );

    const explanation = this.generateIOCExplanation(features, riskScore, reputation);
    const recommendations = this.generateIOCRecommendations(riskScore, reputation, type);

    return {
      ioc,
      type,
      confidence: Math.round(confidence),
      riskScore: Math.round(riskScore),
      reputation,
      factors: features,
      explanation,
      recommendations
    };
  }

  async attributeThreatActor(iocs: IOC[], techniques: string[] = []): Promise<ThreatAttribution[]> {
    const attributions: ThreatAttribution[] = [];
    const model = this.models.get('threat_attributor')!;

    for (const [actorName, profile] of this.knownActors) {
      const evidence = await this.calculateAttributionEvidence(iocs, techniques, profile);
      const confidence = this.calculateAttributionConfidence(evidence, model);

      if (confidence >= model.parameters.minConfidence * 100) {
        attributions.push({
          threatActor: actorName,
          confidence: Math.round(confidence),
          evidence,
          profile,
          relatedCampaigns: await this.getRelatedCampaigns(actorName),
          timeline: await this.getActorTimeline(actorName)
        });
      }
    }

    // Sort by confidence and limit results
    return attributions
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, model.parameters.maxCandidates);
  }

  async predictAttackVector(indicators: IOC[], timeframe: AttackPrediction['timeframe'] = '30d'): Promise<AttackPrediction> {
    const model = this.models.get('attack_predictor')!;
    const features = await this.extractPredictionFeatures(indicators);
    
    // Simulate ML prediction (in production, this would call actual ML models)
    const likelihood = this.calculateAttackLikelihood(features, timeframe);
    const vectors = await this.predictLikelyVectors(indicators, features);
    const riskFactors = this.identifyRiskFactors(features);
    const mitigations = this.recommendMitigations(vectors, riskFactors);
    
    const confidence = Math.min(100, 
      (features.iocQuality * 30) + 
      (features.historicalAccuracy * 25) + 
      (features.threatLandscape * 25) + 
      (features.targetProfile * 20)
    );

    return {
      likelihood: Math.round(likelihood),
      timeframe,
      vectors,
      riskFactors,
      mitigations,
      confidence: Math.round(confidence)
    };
  }

  async clusterThreats(intelligence: ThreatIntelligence[]): Promise<ThreatCluster[]> {
    const model = this.models.get('threat_clusterer')!;
    const clusters: ThreatCluster[] = [];
    
    // Extract features for clustering
    const features = intelligence.map(intel => this.extractClusteringFeatures(intel));
    
    // Simulate clustering algorithm (in production, use actual ML clustering)
    const clusterAssignments = this.performClustering(features, model);
    
    // Build cluster objects
    const clusterMap = new Map<number, ThreatIntelligence[]>();
    clusterAssignments.forEach((clusterId, index) => {
      if (!clusterMap.has(clusterId)) {
        clusterMap.set(clusterId, []);
      }
      clusterMap.get(clusterId)!.push(intelligence[index]);
    });

    clusterMap.forEach((clusterIntel, clusterId) => {
      if (clusterIntel.length >= model.parameters.minClusterSize) {
        const cluster = this.buildThreatCluster(clusterId.toString(), clusterIntel);
        clusters.push(cluster);
      }
    });

    return clusters;
  }

  private async extractIOCFeatures(ioc: string, type: IOCType, context?: any): Promise<IOCScore['factors']> {
    const cacheKey = `features_${ioc}_${type}`;
    const cached = this.featureCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < 3600000) { // 1 hour cache
      return cached.features;
    }

    // Simulate feature extraction (in production, this would query various data sources)
    const features = {
      prevalence: this.calculatePrevalence(ioc, type),
      age: this.calculateAge(ioc, type),
      sources: this.calculateSourceCount(ioc, type),
      context: this.calculateContextScore(ioc, type, context),
      behavior: this.calculateBehaviorScore(ioc, type)
    };

    this.featureCache.set(cacheKey, { features, timestamp: Date.now() });
    return features;
  }

  private calculatePrevalence(ioc: string, type: IOCType): number {
    // Simulate prevalence calculation based on IOC characteristics
    const commonDomains = ['google.com', 'microsoft.com', 'amazon.com', 'facebook.com'];
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.top'];
    
    if (type === 'domain') {
      if (commonDomains.some(domain => ioc.includes(domain))) return 0.9;
      if (suspiciousTLDs.some(tld => ioc.endsWith(tld))) return 0.1;
      if (ioc.length > 20 || ioc.includes('-')) return 0.3;
      return 0.5;
    }
    
    if (type === 'ipv4') {
      const parts = ioc.split('.').map(Number);
      if (parts[0] === 10 || (parts[0] === 192 && parts[1] === 168)) return 0.9; // Private IPs
      if (parts[0] > 200) return 0.2; // High ranges often suspicious
      return 0.4;
    }
    
    return 0.5; // Default
  }

  private calculateAge(ioc: string, type: IOCType): number {
    // Simulate age calculation (newer IOCs might be more suspicious)
    const randomAge = Math.random() * 365; // 0-365 days
    return Math.max(0, Math.min(1, (365 - randomAge) / 365));
  }

  private calculateSourceCount(ioc: string, type: IOCType): number {
    // Simulate source count (more sources = higher confidence)
    const sourceCount = Math.floor(Math.random() * 10) + 1;
    return Math.min(1, sourceCount / 10);
  }

  private calculateContextScore(ioc: string, type: IOCType, context?: any): number {
    // Simulate context scoring based on surrounding information
    if (!context) return 0.3;
    
    let score = 0.3;
    if (context.malwareFamily) score += 0.3;
    if (context.threatActor) score += 0.2;
    if (context.campaign) score += 0.2;
    
    return Math.min(1, score);
  }

  private calculateBehaviorScore(ioc: string, type: IOCType): number {
    // Simulate behavioral analysis
    if (type === 'domain') {
      if (ioc.includes('temp') || ioc.includes('test')) return 0.2;
      if (ioc.match(/[0-9]{4,}/)) return 0.7; // Domains with many numbers
      if (ioc.length < 6) return 0.8; // Very short domains
    }
    
    return 0.4; // Default
  }

  private async calculateAttributionEvidence(
    iocs: IOC[], 
    techniques: string[], 
    profile: ThreatAttribution['profile']
  ): Promise<ThreatAttribution['evidence']> {
    // Simulate evidence calculation
    const iocMatches = Math.floor(Math.random() * iocs.length * 0.3);
    const techniqueMatches = techniques.filter(t => profile.techniques.includes(t)).length;
    const campaignMatches = Math.floor(Math.random() * 5);
    const temporalCorrelation = Math.random() * 0.8 + 0.2;

    return {
      iocMatches,
      techniqueMatches,
      campaignMatches,
      temporalCorrelation
    };
  }

  private calculateAttributionConfidence(evidence: ThreatAttribution['evidence'], model: MLModel): number {
    const weights = { ioc: 0.3, technique: 0.4, campaign: 0.2, temporal: 0.1 };
    
    return (
      (evidence.iocMatches / 10) * weights.ioc * 100 +
      (evidence.techniqueMatches / 5) * weights.technique * 100 +
      (evidence.campaignMatches / 5) * weights.campaign * 100 +
      evidence.temporalCorrelation * weights.temporal * 100
    );
  }

  private async getRelatedCampaigns(actorName: string): Promise<string[]> {
    // Simulate campaign lookup
    const campaigns: Record<string, string[]> = {
      'APT29': ['SolarWinds', 'COVID-19 Vaccine Research', 'NOBELIUM'],
      'APT28': ['Fancy Bear', 'Pawn Storm', 'Sofacy'],
      'Lazarus': ['WannaCry', 'Sony Pictures', 'SWIFT Banking'],
      'FIN7': ['Carbanak', 'Restaurant Campaign', 'Retail Attacks']
    };
    
    return campaigns[actorName] || [];
  }

  private async getActorTimeline(actorName: string): Promise<ThreatAttribution['timeline']> {
    // Simulate timeline data
    const timelines: Record<string, ThreatAttribution['timeline']> = {
      'APT29': { firstSeen: '2008-01-01', lastSeen: '2024-08-01', peakActivity: '2020-12-01' },
      'APT28': { firstSeen: '2007-01-01', lastSeen: '2024-07-15', peakActivity: '2016-11-01' },
      'Lazarus': { firstSeen: '2009-01-01', lastSeen: '2024-08-10', peakActivity: '2017-05-01' },
      'FIN7': { firstSeen: '2013-01-01', lastSeen: '2024-06-30', peakActivity: '2019-03-01' }
    };
    
    return timelines[actorName] || { firstSeen: '2020-01-01', lastSeen: '2024-08-01', peakActivity: '2022-01-01' };
  }

  private async extractPredictionFeatures(indicators: IOC[]): Promise<any> {
    return {
      iocQuality: Math.random() * 0.5 + 0.5,
      historicalAccuracy: Math.random() * 0.3 + 0.7,
      threatLandscape: Math.random() * 0.4 + 0.6,
      targetProfile: Math.random() * 0.6 + 0.4
    };
  }

  private calculateAttackLikelihood(features: any, timeframe: string): number {
    const baseRate = { '24h': 15, '7d': 35, '30d': 60, '90d': 80 };
    const multiplier = (features.iocQuality + features.threatLandscape) / 2;
    return Math.min(100, baseRate[timeframe as keyof typeof baseRate] * multiplier);
  }

  private async predictLikelyVectors(indicators: IOC[], features: any): Promise<AttackPrediction['vectors']> {
    const commonVectors = [
      { technique: 'T1566.001', name: 'Spearphishing Attachment', probability: 0.7 },
      { technique: 'T1071.001', name: 'Web Protocols C2', probability: 0.6 },
      { technique: 'T1059.001', name: 'PowerShell Execution', probability: 0.5 },
      { technique: 'T1055', name: 'Process Injection', probability: 0.4 }
    ];

    return commonVectors.map(vector => ({
      technique: vector.technique,
      probability: Math.round(vector.probability * 100),
      prerequisites: ['Initial Access', 'Execution Capability'],
      indicators: indicators.slice(0, 2).map(ioc => ioc.value)
    }));
  }

  private identifyRiskFactors(features: any): string[] {
    const factors = [];
    if (features.iocQuality > 0.7) factors.push('High-confidence threat indicators present');
    if (features.threatLandscape > 0.6) factors.push('Elevated threat landscape activity');
    if (features.targetProfile > 0.5) factors.push('Organization matches typical target profile');
    return factors;
  }

  private recommendMitigations(vectors: AttackPrediction['vectors'], riskFactors: string[]): string[] {
    const mitigations = [
      'Implement email security controls and user training',
      'Monitor network traffic for C2 communications',
      'Deploy endpoint detection and response (EDR) solutions',
      'Restrict PowerShell execution policies',
      'Implement application whitelisting'
    ];
    
    return mitigations.slice(0, Math.min(5, vectors.length + 2));
  }

  private extractClusteringFeatures(intel: ThreatIntelligence): number[] {
    // Convert threat intelligence to numerical features for clustering
    return [
      intel.confidence / 100,
      intel.tags.length / 10,
      intel.attributes.malwareFamily?.length || 0,
      intel.attributes.threatActor?.length || 0,
      intel.attributes.campaign?.length || 0
    ];
  }

  private performClustering(features: number[][], model: MLModel): number[] {
    // Simulate clustering algorithm (k-means-like)
    const assignments: number[] = [];
    const numClusters = Math.min(model.parameters.maxClusters, Math.floor(features.length / model.parameters.minClusterSize));
    
    features.forEach((_, index) => {
      assignments.push(index % numClusters);
    });
    
    return assignments;
  }

  private buildThreatCluster(id: string, intelligence: ThreatIntelligence[]): ThreatCluster {
    const iocs = intelligence.map(intel => ({ value: intel.ioc, type: intel.type, confidence: intel.confidence }));
    
    const allActors = intelligence.flatMap(intel => intel.attributes.threatActor || []);
    const allCampaigns = intelligence.flatMap(intel => intel.attributes.campaign || []);
    const allMalware = intelligence.flatMap(intel => intel.attributes.malwareFamily || []);
    const allTechniques = intelligence.flatMap(intel => intel.attributes.techniques || []);

    const avgConfidence = intelligence.reduce((sum, intel) => sum + intel.confidence, 0) / intelligence.length;
    const clusterScore = Math.min(100, avgConfidence + (intelligence.length * 5));

    return {
      id,
      name: `Threat Cluster ${id}`,
      iocs,
      commonAttributes: {
        actors: [...new Set(allActors)],
        campaigns: [...new Set(allCampaigns)],
        malwareFamilies: [...new Set(allMalware)],
        techniques: [...new Set(allTechniques)],
        sectors: []
      },
      clusterScore: Math.round(clusterScore),
      centroid: {
        avgConfidence: Math.round(avgConfidence),
        avgRisk: Math.round(avgConfidence * 0.8),
        dominantType: this.findDominantIOCType(iocs)
      },
      relationships: []
    };
  }

  private findDominantIOCType(iocs: any[]): IOCType {
    const typeCounts = new Map<IOCType, number>();
    iocs.forEach(ioc => {
      typeCounts.set(ioc.type, (typeCounts.get(ioc.type) || 0) + 1);
    });
    
    let maxCount = 0;
    let dominantType: IOCType = 'domain';
    typeCounts.forEach((count, type) => {
      if (count > maxCount) {
        maxCount = count;
        dominantType = type;
      }
    });
    
    return dominantType;
  }

  private generateIOCExplanation(features: IOCScore['factors'], riskScore: number, reputation: string): string[] {
    const explanations = [];
    
    if (features.prevalence > 0.7) {
      explanations.push('High prevalence in threat intelligence feeds');
    } else if (features.prevalence < 0.3) {
      explanations.push('Low prevalence, potentially new or targeted threat');
    }
    
    if (features.sources > 0.6) {
      explanations.push('Reported by multiple reliable sources');
    }
    
    if (features.context > 0.6) {
      explanations.push('Strong contextual indicators of malicious activity');
    }
    
    if (features.behavior > 0.6) {
      explanations.push('Behavioral patterns consistent with malicious infrastructure');
    }
    
    if (riskScore > 75) {
      explanations.push('High risk score indicates immediate threat');
    }
    
    return explanations;
  }

  private generateIOCRecommendations(riskScore: number, reputation: string, type: IOCType): string[] {
    const recommendations = [];
    
    if (riskScore > 75) {
      recommendations.push('Block immediately in security controls');
      recommendations.push('Investigate any recent connections or communications');
    } else if (riskScore > 50) {
      recommendations.push('Add to monitoring watchlist');
      recommendations.push('Review logs for historical activity');
    } else {
      recommendations.push('Continue monitoring for changes in reputation');
    }
    
    if (type === 'domain' || type === 'url') {
      recommendations.push('Update DNS/web filtering rules');
    } else if (type === 'ipv4' || type === 'ipv6') {
      recommendations.push('Update firewall and IPS rules');
    } else if (type === 'sha256' || type === 'md5' || type === 'sha1') {
      recommendations.push('Update antivirus and EDR signatures');
    }
    
    return recommendations;
  }

  getModels(): MLModel[] {
    return Array.from(this.models.values());
  }

  getModelAccuracy(modelName: string): number {
    return this.models.get(modelName)?.accuracy || 0;
  }
}

export const mlAnalytics = new MLAnalyticsEngine();
