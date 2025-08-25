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

// CQL template library - expanded with 25+ templates
export const cqlTemplates: CQLTemplate[] = [
  // === NETWORK/DNS/PROXY TEMPLATES ===
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
    id: 'rare-domain-dns',
    name: 'Rare Domains (DNS)',
    description: 'Find rarely seen domains in DNS logs - potential C2 discovery',
    template: `{DNS_REPO}
| groupBy({DOMAIN_FIELD}, function=count())
| where _count < 5 and {DOMAIN_FIELD} != ""
| sort(_count, asc)`,
    placeholders: ['DNS_REPO', 'DOMAIN_FIELD'],
    requiredIOCTypes: [],
    repo: 'dns'
  },
  {
    id: 'dns-beaconing',
    name: 'DNS Beaconing Detection',
    description: 'Detect potential DNS beaconing patterns with regular intervals',
    template: `{DNS_REPO}
| groupBy({DOMAIN_FIELD}, {HOST_FIELD}, function=count())
| where _count > 50
| eval beacon_score=_count/span_duration
| where beacon_score > 0.5
| sort(beacon_score, desc)`,
    placeholders: ['DNS_REPO', 'DOMAIN_FIELD', 'HOST_FIELD'],
    requiredIOCTypes: [],
    repo: 'dns'
  },
  {
    id: 'suspicious-tlds',
    name: 'Suspicious TLD Monitoring',
    description: 'Monitor for domains using suspicious or uncommon TLDs',
    template: `{DNS_REPO}
| regex(field={DOMAIN_FIELD}, pattern=/\\.(tk|ml|ga|cf|pw|cc)$/)
| groupBy({DOMAIN_FIELD}, function=count())
| sort(_count, desc)`,
    placeholders: ['DNS_REPO', 'DOMAIN_FIELD'],
    requiredIOCTypes: [],
    repo: 'dns'
  },

  // === ENDPOINT/EDR TEMPLATES ===
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
    id: 'suspicious-processes',
    name: 'Suspicious Process Execution',
    description: 'Hunt for suspicious process names and command lines',
    template: `{EDR_REPO}
| regex(field={PROC_PATH_FIELD}, pattern=/(powershell|cmd|wscript|cscript|rundll32|regsvr32)\\.exe/i)
| where match(CommandLine, /(-enc|-e|-w hidden|bypass|unrestricted|downloadstring|invoke)/i)
| table({HOST_FIELD}, {USERNAME_FIELD}, {PROC_PATH_FIELD}, CommandLine, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'PROC_PATH_FIELD', 'HOST_FIELD', 'USERNAME_FIELD'],
    requiredIOCTypes: [],
    repo: 'edr'
  },
  {
    id: 'lolbins-hunt',
    name: 'Living-off-the-Land Binaries',
    description: 'Detect abuse of legitimate Windows binaries (LOLBins)',
    template: `{EDR_REPO}
| regex(field={PROC_PATH_FIELD}, pattern=/(certutil|bitsadmin|wmic|mshta|regasm|regsvcs|installutil|msxsl)\\.exe/i)
| where CommandLine != ""
| table({HOST_FIELD}, {USERNAME_FIELD}, {PROC_PATH_FIELD}, CommandLine, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'PROC_PATH_FIELD', 'HOST_FIELD', 'USERNAME_FIELD'],
    requiredIOCTypes: [],
    repo: 'edr'
  },
  {
    id: 'parent-child-anomaly',
    name: 'Parent-Child Process Anomalies',
    description: 'Detect unusual parent-child process relationships',
    template: `{EDR_REPO}
| where ParentImage!="" and {PROC_PATH_FIELD}!=""
| regex(field=ParentImage, pattern=/(winword|excel|powerpnt|acrobat)\\.exe/i)
| regex(field={PROC_PATH_FIELD}, pattern=/(powershell|cmd|wscript|cscript)\\.exe/i)
| table({HOST_FIELD}, {USERNAME_FIELD}, ParentImage, {PROC_PATH_FIELD}, CommandLine, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'PROC_PATH_FIELD', 'HOST_FIELD', 'USERNAME_FIELD'],
    requiredIOCTypes: [],
    repo: 'edr'
  },
  {
    id: 'persistence-registry',
    name: 'Registry Persistence Mechanisms',
    description: 'Hunt for registry-based persistence techniques',
    template: `{EDR_REPO}
| regex(field=TargetObject, pattern=/(run|runonce|winlogon|userinit|shell)/i)
| where {ACTION_FIELD} = "SetValue"
| table({HOST_FIELD}, {USERNAME_FIELD}, TargetObject, Details, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EDR_REPO', 'ACTION_FIELD', 'HOST_FIELD', 'USERNAME_FIELD'],
    requiredIOCTypes: [],
    repo: 'edr'
  },

  // === IDENTITY/AUTHENTICATION TEMPLATES ===
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
    id: 'impossible-travel',
    name: 'Impossible Travel Detection',
    description: 'Detect logins from geographically impossible locations',
    template: `{IDP_REPO}
| where {ACTION_FIELD} = "login" and ResultType = "0"
| stats min(@timestamp) as first_login, max(@timestamp) as last_login by {EMAIL_FIELD}, IPAddress
| eval time_diff = (last_login - first_login) / 1000 / 60 / 60
| where time_diff < 4 and IPAddress != ""
| table({EMAIL_FIELD}, IPAddress, first_login, last_login, time_diff)`,
    placeholders: ['IDP_REPO', 'ACTION_FIELD', 'EMAIL_FIELD'],
    requiredIOCTypes: [],
    repo: 'idp'
  },
  {
    id: 'mfa-fatigue',
    name: 'MFA Fatigue Attack Detection',
    description: 'Detect multiple MFA push notifications (fatigue attacks)',
    template: `{IDP_REPO}
| where {ACTION_FIELD} = "MFA" and ResultType != "0"
| stats count() as mfa_attempts by {EMAIL_FIELD}, IPAddress, bin(@timestamp, 1h)
| where mfa_attempts > 10
| sort(mfa_attempts, desc)`,
    placeholders: ['IDP_REPO', 'ACTION_FIELD', 'EMAIL_FIELD'],
    requiredIOCTypes: [],
    repo: 'idp'
  },
  {
    id: 'failed-logins-spike',
    name: 'Failed Login Spikes',
    description: 'Detect spikes in failed login attempts (potential brute force)',
    template: `{IDP_REPO}
| where {ACTION_FIELD} = "login" and ResultType != "0"
| stats count() as failed_attempts by {EMAIL_FIELD}, IPAddress, bin(@timestamp, 5m)
| where failed_attempts > 5
| sort(failed_attempts, desc)`,
    placeholders: ['IDP_REPO', 'ACTION_FIELD', 'EMAIL_FIELD'],
    requiredIOCTypes: [],
    repo: 'idp'
  },
  {
    id: 'privilege-escalation-audit',
    name: 'Privilege Escalation Audit',
    description: 'Monitor for privilege escalation events and role changes',
    template: `{IDP_REPO}
| where {ACTION_FIELD} in ["AddMember", "RoleAssigned", "PrivilegeGranted"]
| table({EMAIL_FIELD}, {ACTION_FIELD}, TargetRole, ActorUserPrincipalName, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['IDP_REPO', 'ACTION_FIELD', 'EMAIL_FIELD'],
    requiredIOCTypes: [],
    repo: 'idp'
  },

  // === EMAIL SECURITY TEMPLATES ===
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
    id: 'phishing-urls-email',
    name: 'Phishing URLs in Email',
    description: 'Hunt for suspicious URLs in email messages',
    template: `{EMAIL_REPO}
| in({URL_FIELD}, [{URL_LIST}])
| table(SenderAddress, RecipientAddress, Subject, {URL_FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EMAIL_REPO', 'URL_FIELD', 'URL_LIST'],
    requiredIOCTypes: ['urls'],
    repo: 'email'
  },
  {
    id: 'attachment-hash-hunt',
    name: 'Malicious Attachment Hunt',
    description: 'Hunt for malicious file attachments by hash',
    template: `{EMAIL_REPO}
| in({SHA256_FIELD}, [{HASH_LIST}])
| table(SenderAddress, RecipientAddress, Subject, AttachmentName, {SHA256_FIELD}, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EMAIL_REPO', 'SHA256_FIELD', 'HASH_LIST'],
    requiredIOCTypes: ['sha256', 'md5'],
    repo: 'email'
  },
  {
    id: 'email-spoofing',
    name: 'Email Spoofing Detection',
    description: 'Detect potential email spoofing attempts',
    template: `{EMAIL_REPO}
| where SPFResult != "Pass" or DKIMResult != "Pass" or DMARCResult != "Pass"
| table(SenderAddress, RecipientAddress, Subject, SPFResult, DKIMResult, DMARCResult, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['EMAIL_REPO'],
    requiredIOCTypes: [],
    repo: 'email'
  },

  // === CLOUD SECURITY TEMPLATES ===
  {
    id: 'aws-iam-anomalies',
    name: 'AWS IAM Anomalies',
    description: 'Detect unusual AWS IAM activities and policy changes',
    template: `{CLOUD_REPO}
| where eventSource = "iam.amazonaws.com"
| where eventName in ["CreateUser", "CreateRole", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"]
| table(userIdentity.type, userIdentity.principalId, eventName, sourceIPAddress, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['CLOUD_REPO'],
    requiredIOCTypes: [],
    repo: 'cloud'
  },
  {
    id: 'cloud-ip-hunt',
    name: 'Cloud Activity from IOC IPs',
    description: 'Hunt for cloud activities from suspicious IP addresses',
    template: `{CLOUD_REPO}
| in(sourceIPAddress, [{IP_LIST}])
| table(userIdentity.type, userIdentity.principalId, eventName, sourceIPAddress, @timestamp)
| sort(@timestamp, desc)`,
    placeholders: ['CLOUD_REPO', 'IP_LIST'],
    requiredIOCTypes: ['ipv4', 'ipv6'],
    repo: 'cloud'
  },

  // === GENERIC/ENRICHMENT TEMPLATES ===
  {
    id: 'ttp-behavior-hunt',
    name: 'TTP Behavior Hunt',
    description: 'Hunt for specific TTP behaviors across all data sources',
    template: `#type=*
| where match(CommandLine, /{BEHAVIOR_PATTERN}/i) OR match(process_path, /{BEHAVIOR_PATTERN}/i) OR match(event_message, /{BEHAVIOR_PATTERN}/i)
| table(@timestamp, #type, {HOST_FIELD}, {USERNAME_FIELD}, CommandLine, process_path, event_message)
| sort(@timestamp, desc)`,
    placeholders: ['BEHAVIOR_PATTERN', 'HOST_FIELD', 'USERNAME_FIELD'],
    requiredIOCTypes: [],
    repo: 'all'
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
  },
  {
    id: 'timeline-analysis',
    name: 'Timeline Analysis for IOCs',
    description: 'Create a timeline of all IOC-related activities',
    template: `#type=*
| where ({DOMAIN_FIELD} in [{DOMAIN_LIST}] OR {DST_IP_FIELD} in [{IP_LIST}] OR {URL_FIELD} in [{URL_LIST}])
| table(@timestamp, #type, {HOST_FIELD}, {USERNAME_FIELD}, event_details)
| sort(@timestamp, desc)`,
    placeholders: ['DOMAIN_FIELD', 'DST_IP_FIELD', 'URL_FIELD', 'HOST_FIELD', 'USERNAME_FIELD', 'DOMAIN_LIST', 'IP_LIST', 'URL_LIST'],
    requiredIOCTypes: ['domains', 'ipv4', 'ipv6', 'urls'],
    repo: 'all'
  },
  {
    id: 'lateral-movement-detection',
    name: 'Lateral Movement Detection',
    description: 'Detect potential lateral movement using network and authentication logs',
    template: `{IDP_REPO} OR {EDR_REPO}
| where ({ACTION_FIELD} = "login" and sourceIPAddress != "") OR (ProcessName = "net.exe" and CommandLine contains "use")
| stats dc({HOST_FIELD}) as unique_hosts by {USERNAME_FIELD}, sourceIPAddress
| where unique_hosts > 3
| sort(unique_hosts, desc)`,
    placeholders: ['IDP_REPO', 'EDR_REPO', 'ACTION_FIELD', 'HOST_FIELD', 'USERNAME_FIELD'],
    requiredIOCTypes: [],
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
  if (!cql.includes('#type=') && !cql.includes('#Vendor') && !cql.includes('#event.')) {
    errors.push('Query must include a repository selector (#type=, #event.module=, etc.)');
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
  
  // Check for valid operators
  const invalidOperators = cql.match(/[^|\s](=|!=|>|<|>=|<=)[^=]/g);
  if (invalidOperators && invalidOperators.length > 0) {
    errors.push('Check operators - ensure proper spacing and syntax');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

export const renderTemplateWithVendor = (
  template: CQLTemplate,
  iocs: Record<IOCType, string[]>,
  vendorId: string,
  moduleId: string
): { query: string; profile: DataProfile; warnings: string[] } => {
  const { getModuleById } = require('./vendors');
  const module = getModuleById(vendorId, moduleId);
  
  if (!module) {
    return {
      query: template.template,
      profile: defaultProfile,
      warnings: ['Vendor module not found, using default profile']
    };
  }

  // Create a profile from the vendor module
  const vendorProfile: DataProfile = {
    name: `${vendorId}-${moduleId}`,
    description: module.description,
    repos: module.repos,
    fields: module.fields
  };

  const warnings: string[] = [];
  
  // Check if all required placeholders are available
  const missingFields = template.placeholders.filter(placeholder => 
    !vendorProfile.fields[placeholder] && !vendorProfile.repos[placeholder]
  );
  
  if (missingFields.length > 0) {
    warnings.push(`Missing field mappings: ${missingFields.join(', ')}`);
  }

  const query = renderTemplate(template, iocs, vendorProfile);
  
  return { query, profile: vendorProfile, warnings };
};