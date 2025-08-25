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
  return queries.join('\n\n-- Next Query --\n\n');
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