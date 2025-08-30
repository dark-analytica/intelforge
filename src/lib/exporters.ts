import { IOCSet } from './ioc-extractor';

export interface ExportData {
  meta: {
    source_title: string;
    tlp: string;
    generated_at: string;
  };
  iocs: IOCSet;
  ttps: string[];
  profile: string;
  queries: {
    cql: string[];
  };
}

export const exportToQueries = (queries: any[]): string => {
  const header = `# Multi-Vendor Query Bundle\n\nGenerated on: ${new Date().toISOString()}\n\n---\n\n`;
  
  const content = queries.map((queryObj, index) => {
    const query = typeof queryObj === 'string' ? queryObj : queryObj.query || queryObj.cql || queryObj;
    const vendor = queryObj.vendor || 'Unknown';
    const module = queryObj.module || 'Unknown';
    
    // Determine query language based on vendor
    let language = 'cql';
    if (vendor === 'splunk') language = 'spl';
    else if (vendor === 'sentinel') language = 'kql';
    else if (vendor === 'elastic') language = 'esql';
    else if (vendor === 'qradar') language = 'aql';
    else if (vendor === 'chronicle') language = 'udm';
    else if (vendor === 'crowdstrike' || vendor === 'logscale') language = 'cql';
    
    return `## Query ${index + 1} - ${vendor} (${module})\n\n\`\`\`${language}\n${query}\n\`\`\``;
  }).join('\n\n---\n\n');
  
  return header + content;
};

// Legacy function for backward compatibility
export const exportToCQL = (queries: string[]): string => {
  return exportToQueries(queries);
};

export const exportToMitreNavigator = (ttps: any[], metadata?: { title?: string; description?: string; threat_actor?: string }): string => {
  // Calculate confidence scoring based on TTP evidence strength
  const getConfidenceScore = (ttp: any): number => {
    let score = 50; // Base score
    
    if (ttp.evidence_excerpt && ttp.evidence_excerpt.length > 100) score += 20;
    if (ttp.behavior && ttp.behavior.includes('observed')) score += 15;
    if (ttp.tactic) score += 10;
    if (ttp.technique_id && ttp.technique_id.includes('.')) score += 5; // Sub-technique
    
    return Math.min(score, 100);
  };

  // Group techniques by tactic for better visualization
  const tacticGroups = ttps.reduce((groups, ttp) => {
    const tactic = ttp.tactic || 'Unknown';
    if (!groups[tactic]) groups[tactic] = [];
    groups[tactic].push(ttp);
    return groups;
  }, {});

  const navigator = {
    name: metadata?.title || "Threat Intelligence Analysis",
    versions: {
      attack: "14",
      navigator: "4.9.1",
      layer: "4.5"
    },
    domain: "enterprise-attack",
    description: metadata?.description || `Generated from CTI analysis with ${ttps.length} TTPs across ${Object.keys(tacticGroups).length} tactics`,
    filters: {
      platforms: ["windows", "linux", "macos", "azure-ad", "office-365", "saas", "iaas", "google-workspace", "containers"]
    },
    sorting: 0,
    layout: {
      layout: "side",
      aggregateFunction: "average",
      showID: true,
      showName: true,
      showAggregateScores: true,
      countUnscored: false,
      expandedSubtechniques: "annotated"
    },
    hideDisabled: false,
    techniques: ttps.map(ttp => {
      const confidence = getConfidenceScore(ttp);
      return {
        techniqueID: ttp.technique_id,
        tactic: ttp.tactic || "unknown",
        score: confidence,
        color: confidence > 80 ? "#d62728" : confidence > 60 ? "#ff7f0e" : "#2ca02c",
        comment: [
          ttp.behavior || "",
          ttp.evidence_excerpt ? `Evidence: "${ttp.evidence_excerpt.substring(0, 200)}${ttp.evidence_excerpt.length > 200 ? '...' : ''}"` : "",
          metadata?.threat_actor ? `Threat Actor: ${metadata.threat_actor}` : ""
        ].filter(Boolean).join('\n\n'),
        enabled: true,
        metadata: [
          {
            name: "Confidence",
            value: `${confidence}%`
          },
          {
            name: "Tactic",
            value: ttp.tactic || "Unknown"
          },
          {
            name: "Evidence Quality",
            value: ttp.evidence_excerpt ? "High" : "Medium"
          }
        ],
        links: [
          {
            label: "MITRE ATT&CK",
            url: `https://attack.mitre.org/techniques/${ttp.technique_id.replace('.', '/')}/`
          }
        ],
        showSubtechniques: ttp.technique_id.includes('.')
      };
    }),
    gradient: {
      colors: ["#2ca02c", "#ffed4e", "#ff7f0e", "#d62728"],
      minValue: 0,
      maxValue: 100
    },
    legendItems: [
      {
        label: "High Confidence (80-100%)",
        color: "#d62728"
      },
      {
        label: "Medium Confidence (60-79%)",
        color: "#ff7f0e"
      },
      {
        label: "Low Confidence (0-59%)",
        color: "#2ca02c"
      }
    ],
    metadata: [
      {
        name: "Analysis Date",
        value: new Date().toISOString().split('T')[0]
      },
      {
        name: "Total TTPs",
        value: ttps.length.toString()
      },
      {
        name: "Tactics Covered",
        value: Object.keys(tacticGroups).length.toString()
      }
    ],
    links: [
      {
        label: "Generated by CTI Analysis Tool",
        url: "#"
      }
    ],
    showTacticRowBackground: true,
    tacticRowBackground: "#1f2937",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: true
  };
  
  return JSON.stringify(navigator, null, 2);
};

export const exportToCSV = (iocs: IOCSet): string => {
  const rows: string[] = ['type,value'];
  
  Object.entries(iocs).forEach(([type, values]) => {
    values.forEach(value => {
      rows.push(`${type},"${value}"`);
    });
  });
  
  return rows.join('\n');
};

export const exportToSTIX = (iocs: IOCSet, meta: ExportData['meta']): string => {
  const bundle = {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    objects: []
  };

  // Add indicator objects for each IOC
  Object.entries(iocs).forEach(([type, values]) => {
    values.forEach(value => {
      const pattern = getSTIXPattern(type, value);
      if (pattern) {
        bundle.objects.push({
          type: 'indicator',
          id: `indicator--${crypto.randomUUID()}`,
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          pattern,
          labels: ['malicious-activity'],
          spec_version: '2.1'
        });
      }
    });
  });

  return JSON.stringify(bundle, null, 2);
};

const getSTIXPattern = (type: string, value: string): string | null => {
  switch (type) {
    case 'ipv4':
    case 'ipv6':
      return `[network-traffic:src_ref.value = '${value}' OR network-traffic:dst_ref.value = '${value}']`;
    case 'domains':
      return `[domain-name:value = '${value}']`;
    case 'urls':
      return `[url:value = '${value}']`;
    case 'sha256':
      return `[file:hashes.SHA-256 = '${value}']`;
    case 'md5':
      return `[file:hashes.MD5 = '${value}']`;
    case 'emails':
      return `[email-addr:value = '${value}']`;
    default:
      return null;
  }
};

export const exportToJSON = (data: ExportData): string => {
  return JSON.stringify(data, null, 2);
};

export const downloadFile = (content: string, filename: string, mimeType: string) => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};