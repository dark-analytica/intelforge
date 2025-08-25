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

export const exportToCQL = (queries: string[]): string => {
  const header = `# CQL Query Bundle\n\nGenerated on: ${new Date().toISOString()}\n\n---\n\n`;
  const content = queries.map((query, index) => 
    `## Query ${index + 1}\n\n\`\`\`cql\n${query}\n\`\`\``
  ).join('\n\n---\n\n');
  return header + content;
};

export const exportToMitreNavigator = (ttps: any[]): string => {
  const navigator = {
    name: "CTI Analysis",
    versions: {
      attack: "14",
      navigator: "4.9.1",
      layer: "4.5"
    },
    domain: "enterprise-attack",
    description: "Generated from threat intelligence analysis",
    filters: {
      platforms: ["windows", "linux", "macos"]
    },
    sorting: 0,
    layout: {
      layout: "side",
      aggregateFunction: "average",
      showID: false,
      showName: true,
      showAggregateScores: false,
      countUnscored: false
    },
    hideDisabled: false,
    techniques: ttps.map(ttp => ({
      techniqueID: ttp.technique_id,
      tactic: ttp.tactic || "unknown",
      color: "#ff6666",
      comment: ttp.behavior || "",
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: false
    })),
    gradient: {
      colors: ["#ff6666", "#ffe766", "#8ec843"],
      minValue: 0,
      maxValue: 100
    },
    legendItems: [],
    metadata: [],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false
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