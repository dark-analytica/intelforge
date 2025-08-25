export interface Vendor {
  id: string;
  name: string;
  modules: string[];
  repos: Record<string, string>;
  fields: Record<string, string>;
}

export const vendors: Vendor[] = [
  {
    id: 'crowdstrike',
    name: 'CrowdStrike',
    modules: ['falcon-endpoint', 'falcon-sandbox', 'falcon-intelligence'],
    repos: {
      PROXY_REPO: '#type=proxy',
      DNS_REPO: '#type=dns',
      EDR_REPO: '#type=edr #Vendor=CrowdStrike',
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
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    modules: ['defender-endpoint', 'azure-ad', 'office365'],
    repos: {
      PROXY_REPO: '#type=proxy',
      DNS_REPO: '#type=dns',
      EDR_REPO: '#type=edr #Vendor=Microsoft',
      IDP_REPO: '#type=idp #Vendor=Microsoft',
      EMAIL_REPO: '#type=email #Vendor=Microsoft'
    },
    fields: {
      DST_IP_FIELD: 'DestinationIP',
      SRC_IP_FIELD: 'SourceIP',
      DOMAIN_FIELD: 'Domain',
      URL_FIELD: 'Url',
      HOST_FIELD: 'DeviceName',
      USERNAME_FIELD: 'AccountName',
      PROC_PATH_FIELD: 'ProcessCommandLine',
      SHA256_FIELD: 'SHA256',
      MD5_FIELD: 'MD5',
      EMAIL_FIELD: 'UserPrincipalName',
      ACTION_FIELD: 'ActionType'
    }
  },
  {
    id: 'generic',
    name: 'Generic/ECS',
    modules: ['ecs-standard'],
    repos: {
      PROXY_REPO: '#type=proxy',
      DNS_REPO: '#type=dns',
      EDR_REPO: '#type=edr',
      IDP_REPO: '#type=idp',
      EMAIL_REPO: '#type=email'
    },
    fields: {
      DST_IP_FIELD: 'destination.ip',
      SRC_IP_FIELD: 'source.ip',
      DOMAIN_FIELD: 'dns.question.name',
      URL_FIELD: 'url.full',
      HOST_FIELD: 'host.name',
      USERNAME_FIELD: 'user.name',
      PROC_PATH_FIELD: 'process.executable',
      SHA256_FIELD: 'file.hash.sha256',
      MD5_FIELD: 'file.hash.md5',
      EMAIL_FIELD: 'user.email',
      ACTION_FIELD: 'event.action'
    }
  }
];

export interface CPSRule {
  field: string;
  required: boolean;
  type: 'enum' | 'range' | 'presence';
  values?: string[];
  min?: number;
  max?: number;
  message: string;
}

export const cpsRules: CPSRule[] = [
  {
    field: '#Vendor',
    required: true,
    type: 'presence',
    message: 'CPS requires #Vendor tag for proper data classification'
  },
  {
    field: '#event.module',
    required: true,
    type: 'presence',
    message: 'CPS requires #event.module for data source identification'
  },
  {
    field: 'event.severity',
    required: false,
    type: 'range',
    min: 1,
    max: 100,
    message: 'event.severity must be between 1-100 when present'
  },
  {
    field: 'event.kind',
    required: false,
    type: 'enum',
    values: ['alert', 'event', 'metric', 'state', 'pipeline_error', 'signal'],
    message: 'event.kind must be one of: alert, event, metric, state, pipeline_error, signal'
  }
];

export const validateCPS = (query: string, vendor: Vendor, module: string): { valid: boolean; warnings: string[] } => {
  const warnings: string[] = [];
  
  // Check for required vendor tag
  if (!query.includes('#Vendor=')) {
    warnings.push('Missing required #Vendor tag for CPS compliance');
  }
  
  // Check for event.module
  if (!query.includes('#event.module=')) {
    warnings.push('Missing #event.module tag for proper data source identification');
  }
  
  // Check event.kind with category/type requirements
  if (query.includes('event.kind="alert"')) {
    if (!query.includes('event.category') && !query.includes('event.type')) {
      warnings.push('When event.kind="alert", either event.category[] or event.type[] should be specified');
    }
  }
  
  // Check severity range
  const severityMatch = query.match(/event\.severity\s*[=<>!]+\s*(\d+)/);
  if (severityMatch) {
    const severity = parseInt(severityMatch[1]);
    if (severity < 1 || severity > 100) {
      warnings.push('event.severity should be between 1-100');
    }
  }
  
  return {
    valid: warnings.length === 0,
    warnings
  };
};