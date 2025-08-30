import { IOC, IOCType } from './ioc-extractor';

export interface YARARule {
  name: string;
  tags: string[];
  meta: {
    author: string;
    date: string;
    description: string;
    version: string;
    hash?: string;
    reference?: string[];
    severity?: 'low' | 'medium' | 'high' | 'critical';
    family?: string;
    actor?: string;
  };
  strings: YARAString[];
  condition: string;
}

export interface YARAString {
  identifier: string;
  type: 'text' | 'hex' | 'regex';
  value: string;
  modifiers?: string[];
}

export interface YARAGenerationOptions {
  ruleName?: string;
  description?: string;
  author?: string;
  tags?: string[];
  severity?: YARARule['meta']['severity'];
  family?: string;
  actor?: string;
  references?: string[];
  includeMetadata?: boolean;
  stringModifiers?: string[];
}

export interface FileSample {
  name: string;
  hash: string;
  size: number;
  content?: string;
  metadata?: Record<string, any>;
}

export interface MalwareMetadata {
  family?: string;
  variant?: string;
  platform?: string;
  architecture?: string;
  packer?: string;
  compiler?: string;
  language?: string;
  capabilities?: string[];
  behaviors?: string[];
}

class YARAGenerator {
  generateFromIOCs(iocs: IOC[], options: YARAGenerationOptions = {}): YARARule {
    const timestamp = new Date().toISOString().split('T')[0].replace(/-/g, '_');
    const ruleName = options.ruleName || this.generateRuleName(iocs);
    
    // Group IOCs by type for better rule structure
    const iocsByType = this.groupIOCsByType(iocs);
    
    // Generate YARA strings from IOCs
    const strings = this.generateStringsFromIOCs(iocsByType, options);
    
    // Generate condition based on IOC types and count
    const condition = this.generateCondition(strings, iocsByType);
    
    // Generate appropriate tags
    const tags = this.generateTags(iocsByType, options.tags || []);

    const rule: YARARule = {
      name: ruleName,
      tags,
      meta: {
        author: options.author || 'IntelForge',
        date: timestamp,
        description: options.description || this.generateDescription(iocsByType),
        version: '1.0',
        severity: options.severity || this.determineSeverity(iocsByType),
        ...(options.family && { family: options.family }),
        ...(options.actor && { actor: options.actor }),
        ...(options.references && { reference: options.references })
      },
      strings,
      condition
    };

    return rule;
  }

  generateFromFileSamples(
    samples: FileSample[], 
    metadata: MalwareMetadata = {},
    options: YARAGenerationOptions = {}
  ): YARARule {
    const timestamp = new Date().toISOString().split('T')[0].replace(/-/g, '_');
    const ruleName = options.ruleName || this.generateRuleNameFromSamples(samples, metadata);
    
    // Extract strings from file samples
    const strings = this.extractStringsFromSamples(samples, options);
    
    // Generate condition based on sample analysis
    const condition = this.generateConditionFromSamples(strings, samples);
    
    // Generate tags based on metadata
    const tags = this.generateTagsFromMetadata(metadata, options.tags || []);

    const rule: YARARule = {
      name: ruleName,
      tags,
      meta: {
        author: options.author || 'IntelForge',
        date: timestamp,
        description: options.description || this.generateDescriptionFromMetadata(metadata),
        version: '1.0',
        severity: options.severity || 'medium',
        ...(metadata.family && { family: metadata.family }),
        ...(options.actor && { actor: options.actor }),
        ...(samples.length > 0 && { hash: samples[0].hash }),
        ...(options.references && { reference: options.references })
      },
      strings,
      condition
    };

    return rule;
  }

  generateFromThreatIntel(
    iocs: IOC[],
    threatContext: {
      malwareFamily?: string;
      threatActor?: string;
      campaign?: string;
      techniques?: string[];
      platform?: string;
    },
    options: YARAGenerationOptions = {}
  ): YARARule {
    const baseRule = this.generateFromIOCs(iocs, options);
    
    // Enhance with threat intelligence context
    if (threatContext.malwareFamily) {
      baseRule.meta.family = threatContext.malwareFamily;
      baseRule.name = `${threatContext.malwareFamily}_${baseRule.name}`;
      baseRule.tags.push(threatContext.malwareFamily.toLowerCase().replace(/\s+/g, '_'));
    }

    if (threatContext.threatActor) {
      baseRule.meta.actor = threatContext.threatActor;
      baseRule.tags.push(`actor_${threatContext.threatActor.toLowerCase().replace(/\s+/g, '_')}`);
    }

    if (threatContext.campaign) {
      baseRule.meta.description += ` Associated with ${threatContext.campaign} campaign.`;
      baseRule.tags.push(`campaign_${threatContext.campaign.toLowerCase().replace(/\s+/g, '_')}`);
    }

    if (threatContext.platform) {
      baseRule.tags.push(threatContext.platform.toLowerCase());
    }

    return baseRule;
  }

  exportRule(rule: YARARule): string {
    const metaEntries = Object.entries(rule.meta)
      .map(([key, value]) => {
        if (Array.isArray(value)) {
          return value.map(v => `        ${key} = "${v}"`).join('\n');
        }
        return `        ${key} = "${value}"`;
      })
      .join('\n');

    const stringEntries = rule.strings
      .map(str => {
        const modifiers = str.modifiers && str.modifiers.length > 0 
          ? ` ${str.modifiers.join(' ')}`
          : '';
        
        switch (str.type) {
          case 'hex':
            return `        ${str.identifier} = { ${str.value} }${modifiers}`;
          case 'regex':
            return `        ${str.identifier} = /${str.value}/${modifiers}`;
          default:
            return `        ${str.identifier} = "${str.value}"${modifiers}`;
        }
      })
      .join('\n');

    const tags = rule.tags.length > 0 ? ` : ${rule.tags.join(' ')}` : '';

    return `rule ${rule.name}${tags}
{
    meta:
${metaEntries}

    strings:
${stringEntries}

    condition:
        ${rule.condition}
}`;
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

  private generateStringsFromIOCs(
    iocsByType: Map<IOCType, IOC[]>, 
    options: YARAGenerationOptions
  ): YARAString[] {
    const strings: YARAString[] = [];
    let counter = 1;

    iocsByType.forEach((iocs, type) => {
      iocs.forEach(ioc => {
        const identifier = `$${type}_${counter++}`;
        
        switch (type) {
          case 'domain':
          case 'url':
            strings.push({
              identifier,
              type: 'text',
              value: ioc.value,
              modifiers: ['ascii', 'wide', 'nocase']
            });
            break;
          case 'ipv4':
          case 'ipv6':
            strings.push({
              identifier,
              type: 'text',
              value: ioc.value,
              modifiers: ['ascii']
            });
            break;
          case 'sha256':
          case 'md5':
          case 'sha1':
            // Convert hash to hex pattern for binary matching
            strings.push({
              identifier,
              type: 'hex',
              value: this.hashToHexPattern(ioc.value),
              modifiers: []
            });
            break;
          case 'email':
            strings.push({
              identifier,
              type: 'regex',
              value: this.emailToRegex(ioc.value),
              modifiers: ['nocase']
            });
            break;
          default:
            strings.push({
              identifier,
              type: 'text',
              value: ioc.value,
              modifiers: options.stringModifiers || ['ascii', 'wide']
            });
        }
      });
    });

    return strings;
  }

  private extractStringsFromSamples(samples: FileSample[], options: YARAGenerationOptions): YARAString[] {
    const strings: YARAString[] = [];
    let counter = 1;

    samples.forEach(sample => {
      // Extract meaningful strings from file content
      if (sample.content) {
        const extractedStrings = this.extractMeaningfulStrings(sample.content);
        
        extractedStrings.forEach(str => {
          strings.push({
            identifier: `$str_${counter++}`,
            type: 'text',
            value: str,
            modifiers: ['ascii', 'wide']
          });
        });
      }

      // Add file hash as hex pattern
      if (sample.hash) {
        strings.push({
          identifier: `$hash_${counter++}`,
          type: 'hex',
          value: this.hashToHexPattern(sample.hash),
          modifiers: []
        });
      }

      // Add file name pattern
      if (sample.name) {
        strings.push({
          identifier: `$filename_${counter++}`,
          type: 'text',
          value: sample.name,
          modifiers: ['nocase']
        });
      }
    });

    return strings;
  }

  private extractMeaningfulStrings(content: string): string[] {
    const strings: string[] = [];
    
    // Extract URLs
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    const urls = content.match(urlRegex) || [];
    strings.push(...urls);

    // Extract domain names
    const domainRegex = /[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}/g;
    const domains = content.match(domainRegex) || [];
    strings.push(...domains);

    // Extract file paths
    const pathRegex = /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g;
    const paths = content.match(pathRegex) || [];
    strings.push(...paths);

    // Extract registry keys
    const regKeyRegex = /HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*/g;
    const regKeys = content.match(regKeyRegex) || [];
    strings.push(...regKeys);

    // Extract meaningful text strings (4+ characters, alphanumeric)
    const textRegex = /[a-zA-Z0-9]{4,}/g;
    const textStrings = content.match(textRegex) || [];
    
    // Filter out common/generic strings
    const meaningfulText = textStrings.filter(str => 
      !this.isCommonString(str) && str.length >= 4 && str.length <= 50
    );
    
    strings.push(...meaningfulText.slice(0, 10)); // Limit to top 10

    return [...new Set(strings)]; // Remove duplicates
  }

  private isCommonString(str: string): boolean {
    const commonStrings = [
      'this', 'that', 'with', 'have', 'will', 'from', 'they', 'know', 'want',
      'been', 'good', 'much', 'some', 'time', 'very', 'when', 'come', 'here',
      'just', 'like', 'long', 'make', 'many', 'over', 'such', 'take', 'than',
      'them', 'well', 'were', 'data', 'file', 'name', 'size', 'type', 'info'
    ];
    
    return commonStrings.includes(str.toLowerCase()) || 
           /^[0-9]+$/.test(str) || // Pure numbers
           str.length < 4;
  }

  private generateCondition(strings: YARAString[], iocsByType: Map<IOCType, IOC[]>): string {
    if (strings.length === 0) {
      return 'false';
    }

    const totalIOCs = Array.from(iocsByType.values()).reduce((sum, iocs) => sum + iocs.length, 0);
    
    if (totalIOCs === 1) {
      return strings[0].identifier;
    } else if (totalIOCs <= 3) {
      return `any of them`;
    } else if (totalIOCs <= 10) {
      return `2 of them`;
    } else {
      return `3 of them`;
    }
  }

  private generateConditionFromSamples(strings: YARAString[], samples: FileSample[]): string {
    if (strings.length === 0) {
      return 'false';
    }

    const hashStrings = strings.filter(s => s.identifier.includes('hash'));
    const otherStrings = strings.filter(s => !s.identifier.includes('hash'));

    if (hashStrings.length > 0 && otherStrings.length > 0) {
      return `any of (${hashStrings.map(s => s.identifier).join(', ')}) or 2 of (${otherStrings.map(s => s.identifier).join(', ')})`;
    } else if (hashStrings.length > 0) {
      return `any of (${hashStrings.map(s => s.identifier).join(', ')})`;
    } else if (otherStrings.length >= 3) {
      return `2 of them`;
    } else {
      return `any of them`;
    }
  }

  private generateTags(iocsByType: Map<IOCType, IOC[]>, customTags: string[]): string[] {
    const tags = [...customTags];
    
    // Add tags based on IOC types
    if (iocsByType.has('domain') || iocsByType.has('url')) {
      tags.push('network');
      tags.push('c2');
    }

    if (iocsByType.has('sha256') || iocsByType.has('md5') || iocsByType.has('sha1')) {
      tags.push('malware');
      tags.push('hash');
    }

    if (iocsByType.has('email')) {
      tags.push('phishing');
      tags.push('email');
    }

    if (iocsByType.has('ipv4') || iocsByType.has('ipv6')) {
      tags.push('network');
      tags.push('ip');
    }

    return [...new Set(tags)]; // Remove duplicates
  }

  private generateTagsFromMetadata(metadata: MalwareMetadata, customTags: string[]): string[] {
    const tags = [...customTags];
    
    if (metadata.family) {
      tags.push(metadata.family.toLowerCase().replace(/\s+/g, '_'));
    }

    if (metadata.platform) {
      tags.push(metadata.platform.toLowerCase());
    }

    if (metadata.architecture) {
      tags.push(metadata.architecture.toLowerCase());
    }

    if (metadata.packer) {
      tags.push('packed');
      tags.push(metadata.packer.toLowerCase());
    }

    if (metadata.capabilities) {
      metadata.capabilities.forEach(cap => {
        tags.push(cap.toLowerCase().replace(/\s+/g, '_'));
      });
    }

    return [...new Set(tags)]; // Remove duplicates
  }

  private generateRuleName(iocs: IOC[]): string {
    const types = [...new Set(iocs.map(ioc => ioc.type))];
    const typeStr = types.length === 1 ? types[0] : 'multi';
    const timestamp = Date.now().toString().slice(-6);
    return `IntelForge_${typeStr}_${timestamp}`;
  }

  private generateRuleNameFromSamples(samples: FileSample[], metadata: MalwareMetadata): string {
    if (metadata.family) {
      return `${metadata.family.replace(/\s+/g, '_')}_detection`;
    }
    
    if (samples.length > 0 && samples[0].name) {
      const baseName = samples[0].name.replace(/\.[^.]+$/, '').replace(/[^a-zA-Z0-9]/g, '_');
      return `${baseName}_detection`;
    }

    const timestamp = Date.now().toString().slice(-6);
    return `IntelForge_malware_${timestamp}`;
  }

  private generateDescription(iocsByType: Map<IOCType, IOC[]>): string {
    const totalIOCs = Array.from(iocsByType.values()).reduce((sum, iocs) => sum + iocs.length, 0);
    const types = Array.from(iocsByType.keys());
    
    return `Detects suspicious activity based on ${totalIOCs} indicators across ${types.length} IOC types. Generated automatically from threat intelligence.`;
  }

  private generateDescriptionFromMetadata(metadata: MalwareMetadata): string {
    let description = 'Detects malware';
    
    if (metadata.family) {
      description += ` from the ${metadata.family} family`;
    }
    
    if (metadata.platform) {
      description += ` targeting ${metadata.platform}`;
    }
    
    if (metadata.capabilities && metadata.capabilities.length > 0) {
      description += ` with capabilities: ${metadata.capabilities.join(', ')}`;
    }
    
    return description + '. Generated automatically from file analysis.';
  }

  private determineSeverity(iocsByType: Map<IOCType, IOC[]>): YARARule['meta']['severity'] {
    const totalIOCs = Array.from(iocsByType.values()).reduce((sum, iocs) => sum + iocs.length, 0);
    
    if (totalIOCs >= 10) return 'high';
    if (totalIOCs >= 5) return 'medium';
    return 'low';
  }

  private hashToHexPattern(hash: string): string {
    // Convert hash string to hex bytes pattern
    const cleanHash = hash.replace(/[^a-fA-F0-9]/g, '');
    return cleanHash.match(/.{2}/g)?.join(' ') || cleanHash;
  }

  private emailToRegex(email: string): string {
    // Convert email to regex pattern, escaping special characters
    return email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace('@', '\\@');
  }
}

export const yaraGenerator = new YARAGenerator();
