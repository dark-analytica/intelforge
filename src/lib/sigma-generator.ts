import { IOC, IOCType } from './ioc-extractor';
import { getVendorById } from './vendors';

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  author: string;
  date: string;
  modified?: string;
  status: 'experimental' | 'test' | 'stable';
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  references: string[];
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    selection?: Record<string, any>;
    condition: string;
    [key: string]: any;
  };
  falsepositives: string[];
  fields: string[];
}

export interface SigmaGenerationOptions {
  title?: string;
  description?: string;
  author?: string;
  level?: SigmaRule['level'];
  status?: SigmaRule['status'];
  category?: string;
  product?: string;
  service?: string;
  tags?: string[];
  timeframe?: string;
  customFields?: Record<string, string>;
}

export interface SigmaExportFormat {
  platform: string;
  query: string;
  notes?: string;
}

class SigmaGenerator {
  generateFromIOCs(iocs: IOC[], options: SigmaGenerationOptions = {}): SigmaRule {
    const timestamp = new Date().toISOString().split('T')[0];
    const ruleId = this.generateRuleId(iocs);

    // Group IOCs by type for better rule structure
    const iocsByType = this.groupIOCsByType(iocs);
    
    // Generate detection logic based on IOC types
    const detection = this.buildDetectionLogic(iocsByType, options);
    
    // Determine appropriate log source based on IOC types
    const logsource = this.determineLogSource(iocsByType, options);
    
    // Generate appropriate tags based on IOC content
    const tags = this.generateTags(iocsByType, options.tags || []);

    const rule: SigmaRule = {
      id: ruleId,
      title: options.title || this.generateTitle(iocsByType),
      description: options.description || this.generateDescription(iocsByType),
      author: options.author || 'IntelForge',
      date: timestamp,
      status: options.status || 'experimental',
      level: options.level || this.determineSeverityLevel(iocsByType),
      tags,
      references: this.generateReferences(iocs),
      logsource,
      detection,
      falsepositives: this.generateFalsePositives(iocsByType),
      fields: this.generateFields(iocsByType, logsource)
    };

    return rule;
  }

  generateFromThreatIntel(
    iocs: IOC[], 
    threatContext: {
      threatActor?: string;
      campaign?: string;
      malwareFamily?: string;
      techniques?: string[];
      severity?: SigmaRule['level'];
    },
    options: SigmaGenerationOptions = {}
  ): SigmaRule {
    const baseRule = this.generateFromIOCs(iocs, options);
    
    // Enhance with threat intelligence context
    if (threatContext.threatActor) {
      baseRule.tags.push(`attack.group.${threatContext.threatActor.toLowerCase().replace(/\s+/g, '_')}`);
      baseRule.title = `${threatContext.threatActor} - ${baseRule.title}`;
    }

    if (threatContext.campaign) {
      baseRule.tags.push(`campaign.${threatContext.campaign.toLowerCase().replace(/\s+/g, '_')}`);
      baseRule.description += ` Associated with ${threatContext.campaign} campaign.`;
    }

    if (threatContext.malwareFamily) {
      baseRule.tags.push(`malware.${threatContext.malwareFamily.toLowerCase().replace(/\s+/g, '_')}`);
    }

    if (threatContext.techniques) {
      threatContext.techniques.forEach(technique => {
        baseRule.tags.push(`attack.${technique.toLowerCase()}`);
      });
    }

    if (threatContext.severity) {
      baseRule.level = threatContext.severity;
    }

    return baseRule;
  }

  exportToSIEM(rule: SigmaRule, platform: string): SigmaExportFormat {
    switch (platform.toLowerCase()) {
      case 'splunk':
        return this.exportToSplunk(rule);
      case 'elastic':
      case 'elasticsearch':
        return this.exportToElastic(rule);
      case 'qradar':
        return this.exportToQRadar(rule);
      case 'sentinel':
      case 'azure':
        return this.exportToSentinel(rule);
      case 'chronicle':
        return this.exportToChronicle(rule);
      default:
        return {
          platform,
          query: this.exportToGeneric(rule),
          notes: 'Generic Sigma rule format - may need platform-specific adjustments'
        };
    }
  }

  private generateRuleId(iocs: IOC[]): string {
    const content = iocs.map(ioc => ioc.value).join('');
    const hash = this.simpleHash(content);
    return `intelforge-${hash.substring(0, 8)}`;
  }

  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  private groupIOCsByType(iocs: IOC[]): Map<IOCType, IOC[]> {
    const grouped = new Map<IOCType, IOC[]>();
    
    iocs.forEach(ioc => {
      if (!grouped.has(ioc.type)) {
        grouped.set(ioc.type, []);
      }
      grouped.get(ioc.type)!.push(ioc);
    });

    return grouped;
  }

  private buildDetectionLogic(iocsByType: Map<IOCType, IOC[]>, options: SigmaGenerationOptions): SigmaRule['detection'] {
    const selections: Record<string, any> = {};
    const conditions: string[] = [];

    // Build selections for each IOC type
    iocsByType.forEach((iocs, type) => {
      const selectionName = `selection_${type}`;
      const values = iocs.map(ioc => ioc.value);

      switch (type) {
        case 'ipv4':
        case 'ipv6':
          selections[selectionName] = {
            'destination.ip': values,
            'source.ip': values
          };
          break;
        case 'domain':
          selections[selectionName] = {
            'destination.domain': values,
            'dns.question.name': values,
            'url.domain': values
          };
          break;
        case 'url':
          selections[selectionName] = {
            'url.original': values,
            'http.request.uri': values
          };
          break;
        case 'sha256':
        case 'md5':
        case 'sha1':
          selections[selectionName] = {
            'file.hash.sha256': type === 'sha256' ? values : undefined,
            'file.hash.md5': type === 'md5' ? values : undefined,
            'file.hash.sha1': type === 'sha1' ? values : undefined,
            'process.hash.sha256': type === 'sha256' ? values : undefined,
            'process.hash.md5': type === 'md5' ? values : undefined
          };
          // Remove undefined values
          Object.keys(selections[selectionName]).forEach(key => {
            if (selections[selectionName][key] === undefined) {
              delete selections[selectionName][key];
            }
          });
          break;
        case 'email':
          selections[selectionName] = {
            'email.from.address': values,
            'email.to.address': values,
            'email.sender.address': values
          };
          break;
        default:
          selections[selectionName] = {
            'event.original': values.map(v => `*${v}*`)
          };
      }

      conditions.push(selectionName);
    });

    // Add timeframe if specified
    if (options.timeframe) {
      selections['timeframe'] = {
        '@timestamp': `gte|${options.timeframe}`
      };
    }

    return {
      ...selections,
      condition: conditions.length > 1 ? `1 of (${conditions.join(', ')})` : conditions[0] || 'selection'
    };
  }

  private determineLogSource(iocsByType: Map<IOCType, IOC[]>, options: SigmaGenerationOptions): SigmaRule['logsource'] {
    if (options.category || options.product || options.service) {
      return {
        category: options.category,
        product: options.product,
        service: options.service
      };
    }

    // Determine based on IOC types
    const types = Array.from(iocsByType.keys());
    
    if (types.includes('ipv4') || types.includes('ipv6') || types.includes('domain') || types.includes('url')) {
      return {
        category: 'network_connection',
        product: 'firewall'
      };
    }

    if (types.includes('sha256') || types.includes('md5') || types.includes('sha1')) {
      return {
        category: 'process_creation',
        product: 'windows'
      };
    }

    if (types.includes('email')) {
      return {
        category: 'email',
        product: 'exchange'
      };
    }

    return {
      category: 'security'
    };
  }

  private generateTags(iocsByType: Map<IOCType, IOC[]>, customTags: string[]): string[] {
    const tags = [...customTags];
    
    // Add MITRE ATT&CK tags based on IOC types
    if (iocsByType.has('ipv4') || iocsByType.has('ipv6') || iocsByType.has('domain')) {
      tags.push('attack.command_and_control');
      tags.push('attack.t1071'); // Application Layer Protocol
    }

    if (iocsByType.has('url')) {
      tags.push('attack.initial_access');
      tags.push('attack.t1566'); // Phishing
    }

    if (iocsByType.has('sha256') || iocsByType.has('md5') || iocsByType.has('sha1')) {
      tags.push('attack.execution');
      tags.push('attack.t1059'); // Command and Scripting Interpreter
    }

    if (iocsByType.has('email')) {
      tags.push('attack.initial_access');
      tags.push('attack.t1566.001'); // Spearphishing Attachment
    }

    return [...new Set(tags)]; // Remove duplicates
  }

  private generateTitle(iocsByType: Map<IOCType, IOC[]>): string {
    const types = Array.from(iocsByType.keys());
    const typeNames = types.map(type => {
      switch (type) {
        case 'ipv4':
        case 'ipv6':
          return 'IP Address';
        case 'domain':
          return 'Domain';
        case 'url':
          return 'URL';
        case 'sha256':
        case 'md5':
        case 'sha1':
          return 'File Hash';
        case 'email':
          return 'Email Address';
        default:
          return 'IOC';
      }
    });

    const uniqueTypes = [...new Set(typeNames)];
    return `Suspicious ${uniqueTypes.join(' and ')} Activity`;
  }

  private generateDescription(iocsByType: Map<IOCType, IOC[]>): string {
    const totalIOCs = Array.from(iocsByType.values()).reduce((sum, iocs) => sum + iocs.length, 0);
    const types = Array.from(iocsByType.keys());
    
    return `Detects suspicious activity involving ${totalIOCs} known malicious indicators across ${types.length} IOC types. This rule was automatically generated from threat intelligence data.`;
  }

  private determineSeverityLevel(iocsByType: Map<IOCType, IOC[]>): SigmaRule['level'] {
    const totalIOCs = Array.from(iocsByType.values()).reduce((sum, iocs) => sum + iocs.length, 0);
    
    if (totalIOCs >= 10) return 'high';
    if (totalIOCs >= 5) return 'medium';
    return 'low';
  }

  private generateReferences(iocs: IOC[]): string[] {
    const references = new Set<string>();
    
    // Add generic threat intelligence references
    references.add('https://attack.mitre.org/');
    
    // Add IOC-specific references if available
    iocs.forEach(ioc => {
      if (ioc.source) {
        references.add(ioc.source);
      }
    });

    return Array.from(references);
  }

  private generateFalsePositives(iocsByType: Map<IOCType, IOC[]>): string[] {
    const fps: string[] = [];
    
    if (iocsByType.has('ipv4') || iocsByType.has('ipv6')) {
      fps.push('Legitimate network connections to the same IP ranges');
      fps.push('Internal network traffic');
    }

    if (iocsByType.has('domain')) {
      fps.push('Legitimate domain resolutions');
      fps.push('CDN or cloud service domains');
    }

    if (iocsByType.has('url')) {
      fps.push('Legitimate web browsing');
      fps.push('Automated tools or scripts');
    }

    if (iocsByType.has('sha256') || iocsByType.has('md5') || iocsByType.has('sha1')) {
      fps.push('Legitimate software with the same hash');
      fps.push('System files or libraries');
    }

    return fps;
  }

  private generateFields(iocsByType: Map<IOCType, IOC[]>, logsource: SigmaRule['logsource']): string[] {
    const fields = new Set<string>();
    
    // Add timestamp
    fields.add('@timestamp');
    
    // Add fields based on IOC types
    iocsByType.forEach((_, type) => {
      switch (type) {
        case 'ipv4':
        case 'ipv6':
          fields.add('source.ip');
          fields.add('destination.ip');
          fields.add('source.port');
          fields.add('destination.port');
          break;
        case 'domain':
          fields.add('dns.question.name');
          fields.add('destination.domain');
          break;
        case 'url':
          fields.add('url.original');
          fields.add('http.request.method');
          fields.add('user_agent.original');
          break;
        case 'sha256':
        case 'md5':
        case 'sha1':
          fields.add('file.name');
          fields.add('file.path');
          fields.add('process.name');
          fields.add('process.command_line');
          break;
        case 'email':
          fields.add('email.from.address');
          fields.add('email.to.address');
          fields.add('email.subject');
          break;
      }
    });

    // Add common fields based on log source
    if (logsource.category === 'process_creation') {
      fields.add('process.pid');
      fields.add('process.parent.name');
      fields.add('user.name');
    }

    return Array.from(fields);
  }

  private exportToSplunk(rule: SigmaRule): SigmaExportFormat {
    const conditions: string[] = [];
    
    Object.entries(rule.detection).forEach(([key, value]) => {
      if (key === 'condition') return;
      
      if (typeof value === 'object' && value !== null) {
        Object.entries(value).forEach(([field, values]) => {
          if (Array.isArray(values)) {
            const splunkField = this.mapFieldToSplunk(field);
            const valueList = values.map(v => `"${v}"`).join(' OR ');
            conditions.push(`(${splunkField} IN (${valueList}))`);
          }
        });
      }
    });

    const query = `index=* ${conditions.join(' OR ')} | head 100`;
    
    return {
      platform: 'Splunk',
      query,
      notes: 'Adjust index and field names according to your Splunk environment'
    };
  }

  private exportToElastic(rule: SigmaRule): SigmaExportFormat {
    const mustClauses: any[] = [];
    
    Object.entries(rule.detection).forEach(([key, value]) => {
      if (key === 'condition') return;
      
      if (typeof value === 'object' && value !== null) {
        Object.entries(value).forEach(([field, values]) => {
          if (Array.isArray(values)) {
            mustClauses.push({
              terms: {
                [field]: values
              }
            });
          }
        });
      }
    });

    const query = {
      query: {
        bool: {
          should: mustClauses,
          minimum_should_match: 1
        }
      }
    };

    return {
      platform: 'Elasticsearch',
      query: JSON.stringify(query, null, 2),
      notes: 'Use this query in Kibana or via Elasticsearch API'
    };
  }

  private exportToQRadar(rule: SigmaRule): SigmaExportFormat {
    const conditions: string[] = [];
    
    Object.entries(rule.detection).forEach(([key, value]) => {
      if (key === 'condition') return;
      
      if (typeof value === 'object' && value !== null) {
        Object.entries(value).forEach(([field, values]) => {
          if (Array.isArray(values)) {
            const qradarField = this.mapFieldToQRadar(field);
            const valueList = values.map(v => `'${v}'`).join(', ');
            conditions.push(`${qradarField} IN (${valueList})`);
          }
        });
      }
    });

    const query = `SELECT * FROM events WHERE ${conditions.join(' OR ')} LAST 24 HOURS`;
    
    return {
      platform: 'QRadar',
      query,
      notes: 'Adjust field names and time range according to your QRadar configuration'
    };
  }

  private exportToSentinel(rule: SigmaRule): SigmaExportFormat {
    const conditions: string[] = [];
    
    Object.entries(rule.detection).forEach(([key, value]) => {
      if (key === 'condition') return;
      
      if (typeof value === 'object' && value !== null) {
        Object.entries(value).forEach(([field, values]) => {
          if (Array.isArray(values)) {
            const sentinelField = this.mapFieldToSentinel(field);
            const valueList = values.map(v => `"${v}"`).join(', ');
            conditions.push(`${sentinelField} in (${valueList})`);
          }
        });
      }
    });

    const query = `SecurityEvent\n| where ${conditions.join(' or ')}\n| take 100`;
    
    return {
      platform: 'Microsoft Sentinel',
      query,
      notes: 'Adjust table name and field mappings for your Sentinel workspace'
    };
  }

  private exportToChronicle(rule: SigmaRule): SigmaExportFormat {
    const conditions: string[] = [];
    
    Object.entries(rule.detection).forEach(([key, value]) => {
      if (key === 'condition') return;
      
      if (typeof value === 'object' && value !== null) {
        Object.entries(value).forEach(([field, values]) => {
          if (Array.isArray(values)) {
            const chronicleField = this.mapFieldToChronicle(field);
            values.forEach(v => {
              conditions.push(`${chronicleField} = "${v}"`);
            });
          }
        });
      }
    });

    const query = conditions.join(' OR ');
    
    return {
      platform: 'Google Chronicle',
      query,
      notes: 'Use this UDM search query in Chronicle SIEM'
    };
  }

  private exportToGeneric(rule: SigmaRule): string {
    return `title: ${rule.title}
id: ${rule.id}
description: ${rule.description}
author: ${rule.author}
date: ${rule.date}
status: ${rule.status}
level: ${rule.level}
tags:
${rule.tags.map(tag => `  - ${tag}`).join('\n')}
logsource:
${Object.entries(rule.logsource).map(([key, value]) => `  ${key}: ${value}`).join('\n')}
detection:
${Object.entries(rule.detection).map(([key, value]) => {
  if (key === 'condition') {
    return `  condition: ${value}`;
  }
  return `  ${key}:\n${Object.entries(value as Record<string, any>).map(([field, values]) => 
    `    ${field}: ${Array.isArray(values) ? values.join(' | ') : values}`
  ).join('\n')}`;
}).join('\n')}
falsepositives:
${rule.falsepositives.map(fp => `  - ${fp}`).join('\n')}
fields:
${rule.fields.map(field => `  - ${field}`).join('\n')}`;
  }

  private mapFieldToSplunk(field: string): string {
    const mapping: Record<string, string> = {
      'source.ip': 'src_ip',
      'destination.ip': 'dest_ip',
      'destination.domain': 'dest_host',
      'dns.question.name': 'query',
      'url.original': 'url',
      'file.hash.sha256': 'file_hash',
      'process.name': 'process_name'
    };
    return mapping[field] || field;
  }

  private mapFieldToQRadar(field: string): string {
    const mapping: Record<string, string> = {
      'source.ip': 'sourceip',
      'destination.ip': 'destinationip',
      'destination.domain': 'hostname',
      'url.original': 'url',
      'file.hash.sha256': 'filehash'
    };
    return mapping[field] || field;
  }

  private mapFieldToSentinel(field: string): string {
    const mapping: Record<string, string> = {
      'source.ip': 'SourceIP',
      'destination.ip': 'DestinationIP',
      'destination.domain': 'DestinationHostName',
      'process.name': 'ProcessName',
      'file.hash.sha256': 'FileHash'
    };
    return mapping[field] || field;
  }

  private mapFieldToChronicle(field: string): string {
    const mapping: Record<string, string> = {
      'source.ip': 'principal.ip',
      'destination.ip': 'target.ip',
      'destination.domain': 'target.hostname',
      'file.hash.sha256': 'target.file.sha256',
      'process.name': 'target.process.file.full_path'
    };
    return mapping[field] || field;
  }
}

export const sigmaGenerator = new SigmaGenerator();
