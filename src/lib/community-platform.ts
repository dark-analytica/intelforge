import { IOC } from './ioc-extractor';
import { SigmaRule } from './sigma-generator';
import { YARARule } from './yara-generator';

export interface HuntPack {
  id: string;
  name: string;
  description: string;
  author: {
    username: string;
    reputation: number;
    verified: boolean;
  };
  version: string;
  created: string;
  updated: string;
  downloads: number;
  rating: number;
  tags: string[];
  category: 'malware' | 'apt' | 'ransomware' | 'phishing' | 'c2' | 'general';
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  platform: string[];
  content: {
    queries: HuntQuery[];
    rules: DetectionRule[];
    iocs: IOC[];
    documentation: string;
    playbook?: string;
  };
  metadata: {
    threatActors?: string[];
    malwareFamilies?: string[];
    campaigns?: string[];
    techniques: string[];
    references: string[];
    tlp: 'white' | 'green' | 'amber' | 'red';
  };
  validation: {
    tested: boolean;
    testResults?: TestResult[];
    falsePositiveRate?: number;
    coverage?: number;
  };
  community: {
    comments: Comment[];
    forks: number;
    stars: number;
    issues: Issue[];
  };
}

export interface HuntQuery {
  id: string;
  name: string;
  description: string;
  platform: string;
  language: string;
  query: string;
  expectedResults: string;
  notes?: string;
}

export interface DetectionRule {
  id: string;
  type: 'sigma' | 'yara' | 'snort' | 'suricata' | 'custom';
  name: string;
  content: string;
  platform: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
}

export interface TestResult {
  platform: string;
  success: boolean;
  executionTime: number;
  resultCount: number;
  falsePositives: number;
  notes?: string;
  timestamp: string;
}

export interface Comment {
  id: string;
  author: string;
  content: string;
  timestamp: string;
  replies: Comment[];
  votes: number;
}

export interface Issue {
  id: string;
  title: string;
  description: string;
  type: 'bug' | 'enhancement' | 'question' | 'false_positive';
  status: 'open' | 'closed' | 'in_progress';
  author: string;
  created: string;
  updated: string;
  labels: string[];
}

export interface User {
  username: string;
  email: string;
  reputation: number;
  verified: boolean;
  joinDate: string;
  contributions: {
    huntPacks: number;
    comments: number;
    reviews: number;
    downloads: number;
  };
  specializations: string[];
  badges: Badge[];
  following: string[];
  followers: string[];
}

export interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string;
  earned: string;
  rarity: 'common' | 'uncommon' | 'rare' | 'legendary';
}

export interface CommunityStats {
  totalUsers: number;
  totalHuntPacks: number;
  totalDownloads: number;
  activeUsers: number;
  topContributors: User[];
  popularPacks: HuntPack[];
  recentActivity: Activity[];
}

export interface Activity {
  id: string;
  type: 'pack_published' | 'pack_updated' | 'comment_added' | 'issue_created' | 'pack_starred';
  user: string;
  target: string;
  timestamp: string;
  description: string;
}

export interface SearchFilters {
  category?: string[];
  difficulty?: string[];
  platform?: string[];
  tags?: string[];
  author?: string;
  minRating?: number;
  maxAge?: number; // days
  verified?: boolean;
  tested?: boolean;
}

export interface ContributionGuidelines {
  packStructure: {
    requiredFields: string[];
    recommendedFields: string[];
    namingConventions: string[];
  };
  qualityStandards: {
    minimumDocumentation: string;
    testingRequirements: string[];
    codeStandards: string[];
  };
  reviewProcess: {
    stages: string[];
    criteria: string[];
    timeframe: string;
  };
}

class CommunityPlatform {
  private huntPacks: Map<string, HuntPack> = new Map();
  private users: Map<string, User> = new Map();
  private activities: Activity[] = [];
  private guidelines: ContributionGuidelines;

  constructor() {
    this.initializeGuidelines();
    this.seedSampleData();
  }

  private initializeGuidelines() {
    this.guidelines = {
      packStructure: {
        requiredFields: ['name', 'description', 'author', 'content', 'metadata'],
        recommendedFields: ['validation', 'documentation', 'playbook'],
        namingConventions: [
          'Use descriptive, clear names',
          'Include threat actor or malware family if applicable',
          'Avoid special characters except hyphens and underscores'
        ]
      },
      qualityStandards: {
        minimumDocumentation: 'At least 200 words describing the hunt pack purpose, usage, and expected results',
        testingRequirements: [
          'Test on at least one SIEM platform',
          'Document false positive rate',
          'Provide sample data or test scenarios'
        ],
        codeStandards: [
          'Follow platform-specific query best practices',
          'Include comments explaining complex logic',
          'Optimize for performance'
        ]
      },
      reviewProcess: {
        stages: ['Automated validation', 'Community review', 'Expert verification'],
        criteria: ['Functionality', 'Documentation quality', 'Security impact', 'Originality'],
        timeframe: '7-14 days for initial review'
      }
    };
  }

  private seedSampleData() {
    // Sample users
    this.users.set('threat_hunter_pro', {
      username: 'threat_hunter_pro',
      email: 'hunter@example.com',
      reputation: 95,
      verified: true,
      joinDate: '2023-01-15',
      contributions: { huntPacks: 12, comments: 45, reviews: 23, downloads: 1250 },
      specializations: ['APT', 'Ransomware', 'C2 Detection'],
      badges: [
        { id: 'expert', name: 'Expert Contributor', description: 'Published 10+ high-quality hunt packs', icon: '🏆', earned: '2023-06-01', rarity: 'rare' },
        { id: 'verified', name: 'Verified Hunter', description: 'Identity verified by community', icon: '✓', earned: '2023-02-01', rarity: 'uncommon' }
      ],
      following: ['malware_analyst', 'soc_lead'],
      followers: ['junior_analyst', 'security_student', 'incident_responder']
    });

    // Sample hunt pack
    const samplePack: HuntPack = {
      id: 'apt29-cozy-bear-detection',
      name: 'APT29 (Cozy Bear) Detection Pack',
      description: 'Comprehensive hunt pack for detecting APT29/Cozy Bear activities including SolarWinds-style supply chain attacks, COVID-19 vaccine research targeting, and NOBELIUM campaign indicators.',
      author: {
        username: 'threat_hunter_pro',
        reputation: 95,
        verified: true
      },
      version: '2.1.0',
      created: '2023-03-15T10:00:00Z',
      updated: '2024-08-15T14:30:00Z',
      downloads: 847,
      rating: 4.8,
      tags: ['apt29', 'cozy-bear', 'nobelium', 'supply-chain', 'russia'],
      category: 'apt',
      difficulty: 'advanced',
      platform: ['splunk', 'sentinel', 'crowdstrike', 'elastic'],
      content: {
        queries: [
          {
            id: 'q1',
            name: 'SolarWinds DLL Side-Loading',
            description: 'Detects DLL side-loading techniques used by APT29',
            platform: 'splunk',
            language: 'spl',
            query: 'index=windows EventCode=7 | where match(ImageLoaded, "(?i).*\\\\(version|wininet|winhttp)\\.dll$") AND NOT match(Image, "(?i).*\\\\(system32|syswow64)\\\\.*")',
            expectedResults: 'Events showing suspicious DLL loading from non-system directories'
          },
          {
            id: 'q2',
            name: 'TEARDROP Memory-Only Dropper',
            description: 'Hunts for TEARDROP malware memory artifacts',
            platform: 'sentinel',
            language: 'kql',
            query: 'DeviceProcessEvents | where ProcessCommandLine contains "rundll32" and ProcessCommandLine contains "NetSetupSvc.dll"',
            expectedResults: 'Rundll32 executions with NetSetupSvc.dll parameter'
          }
        ],
        rules: [
          {
            id: 'r1',
            type: 'sigma',
            name: 'APT29 PowerShell Empire',
            content: 'title: APT29 PowerShell Empire Usage\ndetection:\n  selection:\n    CommandLine|contains:\n      - "powershell -nop -w hidden -encodedcommand"\n      - "IEX (New-Object Net.WebClient).DownloadString"',
            platform: ['windows'],
            severity: 'high',
            confidence: 85
          }
        ],
        iocs: [
          { value: 'avsvmcloud.com', type: 'domain', confidence: 90 },
          { value: 'freescanonline.com', type: 'domain', confidence: 85 },
          { value: '13.59.205.66', type: 'ipv4', confidence: 80 }
        ],
        documentation: `# APT29 Detection Pack

## Overview
This hunt pack targets APT29 (also known as Cozy Bear, NOBELIUM) activities based on recent campaigns including the SolarWinds supply chain attack and COVID-19 vaccine research targeting.

## Techniques Covered
- T1055: Process Injection
- T1574.002: DLL Side-Loading  
- T1059.001: PowerShell
- T1071.001: Web Protocols

## Usage Instructions
1. Deploy queries to your SIEM platform
2. Tune thresholds based on your environment
3. Correlate alerts with threat intelligence feeds
4. Investigate any positive hits immediately

## False Positives
- Legitimate software using similar DLL loading patterns
- Administrative PowerShell usage
- Development/testing environments`,
        playbook: `# APT29 Incident Response Playbook

## Initial Response (0-1 hour)
1. Isolate affected systems
2. Preserve memory and disk images
3. Collect network traffic captures
4. Notify stakeholders

## Investigation (1-8 hours)
1. Analyze malware samples
2. Map attack timeline
3. Identify lateral movement
4. Assess data exfiltration

## Containment (8-24 hours)
1. Block C2 communications
2. Patch vulnerable systems
3. Reset compromised credentials
4. Deploy additional monitoring`
      },
      metadata: {
        threatActors: ['APT29', 'Cozy Bear', 'NOBELIUM'],
        malwareFamilies: ['TEARDROP', 'SUNBURST', 'SUNSPOT'],
        campaigns: ['SolarWinds', 'NOBELIUM', 'COVID-19 Vaccine Research'],
        techniques: ['T1055', 'T1574.002', 'T1059.001', 'T1071.001'],
        references: [
          'https://attack.mitre.org/groups/G0016/',
          'https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html'
        ],
        tlp: 'white'
      },
      validation: {
        tested: true,
        testResults: [
          {
            platform: 'splunk',
            success: true,
            executionTime: 2.3,
            resultCount: 12,
            falsePositives: 2,
            timestamp: '2024-08-15T10:00:00Z'
          }
        ],
        falsePositiveRate: 0.15,
        coverage: 0.85
      },
      community: {
        comments: [
          {
            id: 'c1',
            author: 'soc_analyst_jane',
            content: 'Excellent pack! Helped us identify APT29 activity in our environment. The PowerShell detection was particularly effective.',
            timestamp: '2024-08-10T15:30:00Z',
            replies: [],
            votes: 8
          }
        ],
        forks: 23,
        stars: 156,
        issues: []
      }
    };

    this.huntPacks.set(samplePack.id, samplePack);
  }

  async publishHuntPack(pack: Omit<HuntPack, 'id' | 'created' | 'downloads' | 'rating' | 'community'>): Promise<string> {
    const id = this.generatePackId(pack.name);
    const timestamp = new Date().toISOString();
    
    const fullPack: HuntPack = {
      ...pack,
      id,
      created: timestamp,
      updated: timestamp,
      downloads: 0,
      rating: 0,
      community: {
        comments: [],
        forks: 0,
        stars: 0,
        issues: []
      }
    };

    // Validate pack structure
    const validation = this.validateHuntPack(fullPack);
    if (!validation.valid) {
      throw new Error(`Pack validation failed: ${validation.errors.join(', ')}`);
    }

    this.huntPacks.set(id, fullPack);
    
    // Record activity
    this.addActivity({
      type: 'pack_published',
      user: pack.author.username,
      target: id,
      description: `Published new hunt pack: ${pack.name}`
    });

    return id;
  }

  async searchHuntPacks(query: string, filters: SearchFilters = {}): Promise<HuntPack[]> {
    let results = Array.from(this.huntPacks.values());

    // Text search
    if (query) {
      const searchTerms = query.toLowerCase().split(' ');
      results = results.filter(pack => 
        searchTerms.every(term =>
          pack.name.toLowerCase().includes(term) ||
          pack.description.toLowerCase().includes(term) ||
          pack.tags.some(tag => tag.toLowerCase().includes(term))
        )
      );
    }

    // Apply filters
    if (filters.category) {
      results = results.filter(pack => filters.category!.includes(pack.category));
    }

    if (filters.difficulty) {
      results = results.filter(pack => filters.difficulty!.includes(pack.difficulty));
    }

    if (filters.platform) {
      results = results.filter(pack => 
        filters.platform!.some(platform => pack.platform.includes(platform))
      );
    }

    if (filters.tags) {
      results = results.filter(pack =>
        filters.tags!.some(tag => pack.tags.includes(tag))
      );
    }

    if (filters.author) {
      results = results.filter(pack => pack.author.username === filters.author);
    }

    if (filters.minRating) {
      results = results.filter(pack => pack.rating >= filters.minRating!);
    }

    if (filters.verified !== undefined) {
      results = results.filter(pack => pack.author.verified === filters.verified);
    }

    if (filters.tested !== undefined) {
      results = results.filter(pack => pack.validation.tested === filters.tested);
    }

    if (filters.maxAge) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - filters.maxAge);
      results = results.filter(pack => new Date(pack.updated) >= cutoffDate);
    }

    // Sort by relevance (rating + downloads)
    results.sort((a, b) => {
      const scoreA = a.rating * 0.7 + Math.log(a.downloads + 1) * 0.3;
      const scoreB = b.rating * 0.7 + Math.log(b.downloads + 1) * 0.3;
      return scoreB - scoreA;
    });

    return results;
  }

  async getHuntPack(id: string): Promise<HuntPack | null> {
    return this.huntPacks.get(id) || null;
  }

  async downloadHuntPack(id: string, userId: string): Promise<HuntPack | null> {
    const pack = this.huntPacks.get(id);
    if (!pack) return null;

    // Increment download count
    pack.downloads++;
    
    // Record activity
    this.addActivity({
      type: 'pack_starred',
      user: userId,
      target: id,
      description: `Downloaded hunt pack: ${pack.name}`
    });

    return pack;
  }

  async forkHuntPack(id: string, userId: string, modifications: Partial<HuntPack>): Promise<string> {
    const originalPack = this.huntPacks.get(id);
    if (!originalPack) {
      throw new Error('Hunt pack not found');
    }

    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Create forked pack
    const forkedPack: HuntPack = {
      ...originalPack,
      ...modifications,
      id: this.generatePackId(`${originalPack.name}-fork`),
      author: {
        username: userId,
        reputation: user.reputation,
        verified: user.verified
      },
      created: new Date().toISOString(),
      updated: new Date().toISOString(),
      downloads: 0,
      rating: 0,
      community: {
        comments: [],
        forks: 0,
        stars: 0,
        issues: []
      }
    };

    const newId = await this.publishHuntPack(forkedPack);
    
    // Increment fork count on original
    originalPack.community.forks++;

    return newId;
  }

  async addComment(packId: string, userId: string, content: string, parentId?: string): Promise<string> {
    const pack = this.huntPacks.get(packId);
    if (!pack) {
      throw new Error('Hunt pack not found');
    }

    const commentId = `comment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const comment: Comment = {
      id: commentId,
      author: userId,
      content,
      timestamp: new Date().toISOString(),
      replies: [],
      votes: 0
    };

    if (parentId) {
      // Add as reply
      const parentComment = this.findComment(pack.community.comments, parentId);
      if (parentComment) {
        parentComment.replies.push(comment);
      }
    } else {
      // Add as top-level comment
      pack.community.comments.push(comment);
    }

    this.addActivity({
      type: 'comment_added',
      user: userId,
      target: packId,
      description: `Added comment to hunt pack: ${pack.name}`
    });

    return commentId;
  }

  async starHuntPack(packId: string, userId: string): Promise<void> {
    const pack = this.huntPacks.get(packId);
    if (!pack) {
      throw new Error('Hunt pack not found');
    }

    pack.community.stars++;
    
    this.addActivity({
      type: 'pack_starred',
      user: userId,
      target: packId,
      description: `Starred hunt pack: ${pack.name}`
    });
  }

  async reportIssue(packId: string, userId: string, issue: Omit<Issue, 'id' | 'created' | 'updated'>): Promise<string> {
    const pack = this.huntPacks.get(packId);
    if (!pack) {
      throw new Error('Hunt pack not found');
    }

    const issueId = `issue_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const fullIssue: Issue = {
      ...issue,
      id: issueId,
      author: userId,
      created: new Date().toISOString(),
      updated: new Date().toISOString()
    };

    pack.community.issues.push(fullIssue);

    this.addActivity({
      type: 'issue_created',
      user: userId,
      target: packId,
      description: `Reported issue: ${issue.title}`
    });

    return issueId;
  }

  async getCommunityStats(): Promise<CommunityStats> {
    const users = Array.from(this.users.values());
    const packs = Array.from(this.huntPacks.values());

    return {
      totalUsers: users.length,
      totalHuntPacks: packs.length,
      totalDownloads: packs.reduce((sum, pack) => sum + pack.downloads, 0),
      activeUsers: users.filter(user => 
        new Date().getTime() - new Date(user.joinDate).getTime() < 30 * 24 * 60 * 60 * 1000
      ).length,
      topContributors: users
        .sort((a, b) => b.reputation - a.reputation)
        .slice(0, 10),
      popularPacks: packs
        .sort((a, b) => b.downloads - a.downloads)
        .slice(0, 10),
      recentActivity: this.activities.slice(-20).reverse()
    };
  }

  getContributionGuidelines(): ContributionGuidelines {
    return this.guidelines;
  }

  private validateHuntPack(pack: HuntPack): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check required fields
    if (!pack.name || pack.name.length < 5) {
      errors.push('Name must be at least 5 characters long');
    }

    if (!pack.description || pack.description.length < 50) {
      errors.push('Description must be at least 50 characters long');
    }

    if (!pack.content.queries || pack.content.queries.length === 0) {
      errors.push('At least one query is required');
    }

    if (!pack.metadata.techniques || pack.metadata.techniques.length === 0) {
      errors.push('At least one MITRE ATT&CK technique must be specified');
    }

    if (!pack.content.documentation || pack.content.documentation.length < 200) {
      errors.push('Documentation must be at least 200 characters long');
    }

    // Validate queries
    pack.content.queries.forEach((query, index) => {
      if (!query.query || query.query.length < 10) {
        errors.push(`Query ${index + 1}: Query content is too short`);
      }
      if (!query.platform || !query.language) {
        errors.push(`Query ${index + 1}: Platform and language are required`);
      }
    });

    return {
      valid: errors.length === 0,
      errors
    };
  }

  private generatePackId(name: string): string {
    const slug = name.toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .substring(0, 50);
    
    const timestamp = Date.now().toString().slice(-6);
    return `${slug}-${timestamp}`;
  }

  private findComment(comments: Comment[], id: string): Comment | null {
    for (const comment of comments) {
      if (comment.id === id) return comment;
      const found = this.findComment(comment.replies, id);
      if (found) return found;
    }
    return null;
  }

  private addActivity(activity: Omit<Activity, 'id' | 'timestamp'>) {
    this.activities.push({
      ...activity,
      id: `activity_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString()
    });

    // Keep only last 1000 activities
    if (this.activities.length > 1000) {
      this.activities = this.activities.slice(-1000);
    }
  }
}

export const communityPlatform = new CommunityPlatform();
