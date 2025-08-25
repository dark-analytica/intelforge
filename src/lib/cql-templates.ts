export interface CQLTemplate {
  id: string;
  name: string;
  description: string;
  template: string;
  placeholders: string[];
  requiredIOCTypes: IOCType[];
  repo: string;
}

export type IOCType = 'ipv4' | 'ipv6' | 'domains' | 'urls' | 'sha256' | 'md5' | 'emails';

export interface DataProfile {
  name: string;
  description: string;
  repos: Record<string, string>;
  fields: Record<string, string>;
}

// Default data profile
export const defaultProfile: DataProfile = {
  name: 'Default CrowdStrike',
  description: 'Standard CrowdStrike NG-SIEM field mappings',
  repos: {
    PROXY_REPO: '#type=proxy',
    DNS_REPO: '#type=dns', 
    EDR_REPO: '#type=edr',
    IDP_REPO: '#type=idp',
    EMAIL_REPO: '#type=email'
  },
  fields: {
    DST_IP_FIELD: 'dst_ip',
    SRC_IP_FIELD: 'src_ip', 
    DOMAIN_FIELD: 'domain',
    URL_FIELD: 'url',
    HOST_FIELD: 'host',
    USERNAME_FIELD: 'user',
    PROC_PATH_FIELD: 'process_path',
    SHA256_FIELD: 'sha256',
    MD5_FIELD: 'md5',
    EMAIL_FIELD: 'email',
    ACTION_FIELD: 'action'
  }
};

// CQL template library
export const cqlTemplates: CQLTemplate[] = [
  {
    id: 'ip-proxy-hunt',
    name: 'IP Address Hunt (Proxy)',
    description: 'Hunt for suspicious IP addresses in proxy logs',
    template: `{PROXY_REPO}
| in({DST_IP_FIELD}, [{IP_LIST}])
| timechart(span=1h, by={DST_IP_FIELD})
| sort(@timestamp, desc)`,
    placeholders: ['PROXY_REPO', 'DST_IP_FIELD', 'IP_LIST'],
    requiredIOCTypes: ['ipv4', 'ipv6'],
    repo: 'proxy'
  },
  {
    id: 'domain-dns-hunt',
    name: 'Domain Hunt (DNS/Proxy)',
    description: 'Hunt for suspicious domains in DNS and proxy logs',
    template: `{DNS_REPO} OR {PROXY_REPO}
| in({DOMAIN_FIELD}, [{DOMAIN_LIST}])
| groupBy({HOST_FIELD}, function=count())
| sort(_count, desc)`,
    placeholders: ['DNS_REPO', 'PROXY_REPO', 'DOMAIN_FIELD', 'HOST_FIELD', 'DOMAIN_LIST'],
    requiredIOCTypes: ['domains'],
    repo: 'dns'
  },
  {
    id: 'url-proxy-hunt',
    name: 'URL Hunt (Proxy)',
    description: 'Hunt for suspicious URLs in proxy logs',
    template: `{PROXY_REPO}
| in({URL_FIELD}, [{URL_LIST}])
| table({HOST_FIELD}, {URL_FIELD}, {USERNAME_FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['PROXY_REPO', 'URL_FIELD', 'HOST_FIELD', 'USERNAME_FIELD', 'URL_LIST'],
    requiredIOCTypes: ['urls'],
    repo: 'proxy'
  },
  {
    id: 'hash-edr-hunt',
    name: 'File Hash Hunt (EDR)',
    description: 'Hunt for malicious file hashes in endpoint data',
    template: `{EDR_REPO}
| in({SHA256_FIELD}, [{HASH_LIST}])
| table({HOST_FIELD}, {USERNAME_FIELD}, {PROC_PATH_FIELD}, {SHA256_FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'SHA256_FIELD', 'HOST_FIELD', 'USERNAME_FIELD', 'PROC_PATH_FIELD', 'HASH_LIST'],
    requiredIOCTypes: ['sha256', 'md5'],
    repo: 'edr'
  },
  {
    id: 'ip-edr-network',
    name: 'EDR Network Connections to IOC IPs',
    description: 'Endpoint processes connecting to known bad IPs',
    template: `{EDR_REPO}
| in({DST_IP_FIELD}, [{IP_LIST}])
| table({HOST_FIELD}, {USERNAME_FIELD}, {PROC_PATH_FIELD}, {DST_IP_FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'DST_IP_FIELD', 'HOST_FIELD', 'USERNAME_FIELD', 'PROC_PATH_FIELD', 'IP_LIST'],
    requiredIOCTypes: ['ipv4', 'ipv6'],
    repo: 'edr'
  },
  {
    id: 'email-idp-hunt',
    name: 'Email Hunt (Identity)',
    description: 'Hunt for suspicious email addresses in identity provider logs',
    template: `{IDP_REPO}
| in({EMAIL_FIELD}, [{EMAIL_LIST}])
| where {ACTION_FIELD} = "login"
| groupBy({EMAIL_FIELD}, function=count())
| sort(_count, desc)`,
    placeholders: ['IDP_REPO', 'EMAIL_FIELD', 'ACTION_FIELD', 'EMAIL_LIST'],
    requiredIOCTypes: ['emails'],
    repo: 'idp'
  },
  {
    id: 'email-email-repo',
    name: 'Email Indicators (Email Sec)',
    description: 'Search email security logs for indicators',
    template: `{EMAIL_REPO}
| in({EMAIL_FIELD}, [{EMAIL_LIST}])
| groupBy({EMAIL_FIELD}, function=count())
| sort(_count, desc)`,
    placeholders: ['EMAIL_REPO', 'EMAIL_FIELD', 'EMAIL_LIST'],
    requiredIOCTypes: ['emails'],
    repo: 'email'
  },
  {
    id: 'rare-domain-dns',
    name: 'Rare Domains (DNS)',
    description: 'Find rarely seen domains in DNS in the last interval',
    template: `{DNS_REPO}
| groupBy({DOMAIN_FIELD}, function=count())
| where _count < 5 and {DOMAIN_FIELD} != ""
| sort(_count, asc)`,
    placeholders: ['DNS_REPO', 'DOMAIN_FIELD'],
    requiredIOCTypes: ['domains'],
    repo: 'dns'
  },
  {
    id: 'ioc-enrichment',
    name: 'IOC Enrichment Lookup',
    description: 'Perform IOC enrichment across all data sources',
    template: `#type=*
| ioc:lookup(field={FIELD}, confidenceThreshold=high)
| where ioc.match = true
| table(ioc.type, ioc.indicator, {FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['FIELD'],
    requiredIOCTypes: ['domains', 'ipv4', 'ipv6'],
    repo: 'all'
  }
];
    name: 'Domain Hunt (DNS/Proxy)',
    description: 'Hunt for suspicious domains in DNS and proxy logs',
    template: `{DNS_REPO} OR {PROXY_REPO}
| ({DOMAIN_FIELD} =? "{DOMAIN}" OR regex(field={URL_FIELD}, pattern="/(^|\\.){DOMAIN_ESCAPED}$/"))
| groupBy({HOST_FIELD}, function=count())
| sort(_count, desc)`,
    placeholders: ['DNS_REPO', 'PROXY_REPO', 'DOMAIN_FIELD', 'URL_FIELD', 'HOST_FIELD', 'DOMAIN', 'DOMAIN_ESCAPED'],
    requiredIOCTypes: ['domains'],
    repo: 'dns'
  },
  {
    id: 'hash-edr-hunt',
    name: 'File Hash Hunt (EDR)',
    description: 'Hunt for malicious file hashes in endpoint data',
    template: `{EDR_REPO}
| in({SHA256_FIELD}, [{HASH_LIST}])
| table({HOST_FIELD}, {USERNAME_FIELD}, {PROC_PATH_FIELD}, {SHA256_FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'SHA256_FIELD', 'HOST_FIELD', 'USERNAME_FIELD', 'PROC_PATH_FIELD', 'HASH_LIST'],
    requiredIOCTypes: ['sha256', 'md5'],
    repo: 'edr'
  },
  {
    id: 'email-idp-hunt',
    name: 'Email Hunt (Identity)',
    description: 'Hunt for suspicious email addresses in identity provider logs',
    template: `{IDP_REPO}
| in({EMAIL_FIELD}, [{EMAIL_LIST}])
| where {ACTION_FIELD} = "login"
| groupBy({EMAIL_FIELD}, function=count())
| sort(_count, desc)`,
    placeholders: ['IDP_REPO', 'EMAIL_FIELD', 'ACTION_FIELD', 'EMAIL_LIST'],
    requiredIOCTypes: ['emails'],
    repo: 'idp'
  },
  {
    id: 'ioc-enrichment',
    name: 'IOC Enrichment Lookup',
    description: 'Perform IOC enrichment across all data sources',
    template: `#type=*
| ioc:lookup(field={FIELD}, confidenceThreshold=high)
| where ioc.match = true
| table(ioc.type, ioc.indicator, {FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['FIELD'],
    requiredIOCTypes: ['domains', 'ipv4', 'ipv6'],
    repo: 'all'
  }
];

export const renderTemplate = (
  template: CQLTemplate, 
  iocs: Record<IOCType, string[]>,
  profile: DataProfile = defaultProfile
): string => {
  let rendered = template.template;
  
  // Replace repository placeholders
  Object.entries(profile.repos).forEach(([key, value]) => {
    rendered = rendered.replace(new RegExp(`{${key}}`, 'g'), value);
  });
  
  // Replace field placeholders
  Object.entries(profile.fields).forEach(([key, value]) => {
    rendered = rendered.replace(new RegExp(`{${key}}`, 'g'), value);
  });
  
  // Replace IOC list placeholders
  if (template.requiredIOCTypes.includes('ipv4') || template.requiredIOCTypes.includes('ipv6')) {
    const ipList = [...iocs.ipv4, ...iocs.ipv6].map(ip => `"${ip}"`).join(', ');
    rendered = rendered.replace(/{IP_LIST}/g, ipList);
  }

  if (template.requiredIOCTypes.includes('sha256') || template.requiredIOCTypes.includes('md5')) {
    const hashList = [...iocs.sha256, ...iocs.md5].map(hash => `"${hash}"`).join(', ');
    rendered = rendered.replace(/{HASH_LIST}/g, hashList);
  }

  if (template.requiredIOCTypes.includes('emails')) {
    const emailList = iocs.emails.map(email => `"${email}"`).join(', ');
    rendered = rendered.replace(/{EMAIL_LIST}/g, emailList);
  }

  if (iocs.domains.length > 0) {
    const domainList = iocs.domains.map(d => `"${d}"`).join(', ');
    rendered = rendered.replace(/{DOMAIN_LIST}/g, domainList);
  }

  if (iocs.urls.length > 0) {
    const urlList = iocs.urls.map(u => `"${u}"`).join(', ');
    rendered = rendered.replace(/{URL_LIST}/g, urlList);
  }

  // Replace single domain placeholders (for domain templates)
  if (template.requiredIOCTypes.includes('domains') && iocs.domains.length > 0) {
    rendered = rendered.replace(/{DOMAIN}/g, iocs.domains[0]);
    rendered = rendered.replace(/{DOMAIN_ESCAPED}/g, iocs.domains[0].replace(/\./g, '\\.'));
  }
  
  return rendered;
};

export const validateCQLSyntax = (cql: string): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  // Basic syntax validation
  if (!cql.includes('#type=') && !cql.includes('#Vendor')) {
    errors.push('Query must include a repository selector (#type=) or vendor tag (#Vendor)');
  }
  
  // Check for balanced parentheses
  const openParens = (cql.match(/\(/g) || []).length;
  const closeParens = (cql.match(/\)/g) || []).length;
  if (openParens !== closeParens) {
    errors.push('Unbalanced parentheses in query');
  }
  
  // Check for balanced quotes
  const quotes = (cql.match(/"/g) || []).length;
  if (quotes % 2 !== 0) {
    errors.push('Unbalanced quotes in query');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};