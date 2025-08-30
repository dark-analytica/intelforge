export interface VendorModule {
  id: string;
  name: string;
  description: string;
  fields: Record<string, string>;
  repos: Record<string, string>;
  validation?: {
    required_fields?: string[];
    cps_modules?: string[];
    notes?: string[];
  };
}

export interface Vendor {
  id: string;
  name: string;
  description: string;
  modules: VendorModule[];
  documentation_url?: string;
  queryLanguage?: string;
  documentation?: string;
}

export const vendors: Vendor[] = [
  {
    id: 'crowdstrike',
    name: 'CrowdStrike LogScale',
    description: 'CrowdStrike Falcon LogScale (formerly Humio) with CQL query language',
    documentation_url: 'https://library.humio.com/falcon-logscale/docs/cql/',
    modules: [
      {
        id: 'falcon-data-replicator',
        name: 'Falcon Data Replicator (Default)',
        description: 'Standard CrowdStrike endpoint and network telemetry via FDR',
        fields: {
          DST_IP_FIELD: 'aip',
          SRC_IP_FIELD: 'LocalIP', 
          DOMAIN_FIELD: 'DomainName',
          URL_FIELD: 'URL',
          HOST_FIELD: 'ComputerName',
          USERNAME_FIELD: 'UserName',
          PROC_PATH_FIELD: 'ImageFileName',
          SHA256_FIELD: 'SHA256HashData',
          MD5_FIELD: 'MD5HashData',
          EMAIL_FIELD: 'EmailAddress',
          ACTION_FIELD: 'EventType'
        },
        repos: {
          PROXY_REPO: '#event.module=crowdstrike #event.category=network',
          DNS_REPO: '#event.module=crowdstrike #event.category=network OR #event.dataset=dns',
          EDR_REPO: '#event.module=crowdstrike #event.category=process',
          IDP_REPO: '#event.module=crowdstrike #event.category=authentication',
          EMAIL_REPO: '#event.module=crowdstrike #event.category=email'
        },
        validation: {
          cps_modules: ['endpoint', 'network', 'authentication'],
          required_fields: ['ComputerName', 'EventType', 'UserName'],
          notes: ['Ensure Falcon Data Replicator is configured', 'CPS field standardization required']
        }
      },
      {
        id: 'crowdstrike-cloud',
        name: 'CrowdStrike Cloud Detection',
        description: 'CrowdStrike cloud workload protection and detection telemetry',
        fields: {
          DST_IP_FIELD: 'dst_ip',
          SRC_IP_FIELD: 'src_ip',
          DOMAIN_FIELD: 'domain',
          URL_FIELD: 'url', 
          HOST_FIELD: 'instance_id',
          USERNAME_FIELD: 'user_name',
          PROC_PATH_FIELD: 'process_path',
          SHA256_FIELD: 'file_hash_sha256',
          MD5_FIELD: 'file_hash_md5',
          EMAIL_FIELD: 'email',
          ACTION_FIELD: 'action'
        },
        repos: {
          PROXY_REPO: '#event.module=crowdstrike-cloud #event.category=network',
          DNS_REPO: '#event.module=crowdstrike-cloud #event.category=network',
          EDR_REPO: '#event.module=crowdstrike-cloud #event.category=process',
          IDP_REPO: '#event.module=crowdstrike-cloud #event.category=iam',
          EMAIL_REPO: '#event.module=crowdstrike-cloud #event.category=email'
        },
        validation: {
          cps_modules: ['cloud', 'iam'],
          required_fields: ['instance_id', 'action'],
          notes: ['Cloud workload protection module required']
        }
      }
    ]
  },
  {
    id: 'logscale',
    name: 'LogScale (Self-Hosted)', 
    description: 'Self-hosted LogScale/Humio platform with standard log parsing',
    documentation_url: 'https://library.humio.com/humio-server/docs/',
    modules: [
      {
        id: 'logscale-standard',
        name: 'LogScale Standard Fields',
        description: 'Standard LogScale/Humio field mappings for common log sources',
        fields: {
          DST_IP_FIELD: 'dst_ip',
          SRC_IP_FIELD: 'src_ip',
          DOMAIN_FIELD: 'dns.question.name',
          URL_FIELD: 'url',
          HOST_FIELD: 'host',
          USERNAME_FIELD: 'user.name',
          PROC_PATH_FIELD: 'process.executable',
          SHA256_FIELD: 'file.hash.sha256',
          MD5_FIELD: 'file.hash.md5', 
          EMAIL_FIELD: 'user.email',
          ACTION_FIELD: 'event.action'
        },
        repos: {
          PROXY_REPO: '#type=proxy',
          DNS_REPO: '#type=dns',
          EDR_REPO: '#type=endpoint', 
          IDP_REPO: '#type=authentication',
          EMAIL_REPO: '#type=email'
        },
        validation: {
          required_fields: ['@timestamp', 'host'],
          notes: ['Standard ECS field mapping', 'Ensure log parsers are configured']
        }
      },
      {
        id: 'logscale-syslog',
        name: 'LogScale Syslog/Raw Logs',
        description: 'Raw syslog and unstructured log ingestion with basic parsing',
        fields: {
          DST_IP_FIELD: 'dest_ip',
          SRC_IP_FIELD: 'source_ip',
          DOMAIN_FIELD: 'domain',
          URL_FIELD: 'url',
          HOST_FIELD: 'hostname',
          USERNAME_FIELD: 'username',
          PROC_PATH_FIELD: 'process',
          SHA256_FIELD: 'sha256',
          MD5_FIELD: 'md5',
          EMAIL_FIELD: 'email',
          ACTION_FIELD: 'action'
        },
        repos: {
          PROXY_REPO: 'sourcetype=proxy',
          DNS_REPO: 'sourcetype=dns',
          EDR_REPO: 'sourcetype=endpoint',
          IDP_REPO: 'sourcetype=auth',
          EMAIL_REPO: 'sourcetype=email'
        },
        validation: {
          required_fields: ['@rawstring', 'hostname'],
          notes: ['Raw log parsing - field extraction may be limited', 'Configure parsers for better field extraction']
        }
      }
    ]
  },
  {
    id: 'splunk',
    name: 'Splunk Enterprise/Cloud',
    description: 'Splunk Search Processing Language (SPL) with standard field mappings',
    documentation_url: 'https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/',
    modules: [
      {
        id: 'splunk-enterprise',
        name: 'Splunk Enterprise',
        description: 'Standard Splunk Enterprise with Common Information Model (CIM)',
        fields: {
          DST_IP_FIELD: 'dest_ip',
          SRC_IP_FIELD: 'src_ip',
          DOMAIN_FIELD: 'query',
          URL_FIELD: 'url',
          HOST_FIELD: 'host',
          USERNAME_FIELD: 'user',
          PROC_PATH_FIELD: 'process',
          SHA256_FIELD: 'file_hash',
          MD5_FIELD: 'file_hash',
          EMAIL_FIELD: 'src_user',
          ACTION_FIELD: 'action'
        },
        repos: {
          PROXY_REPO: 'index=proxy',
          DNS_REPO: 'index=dns',
          EDR_REPO: 'index=endpoint',
          IDP_REPO: 'index=authentication',
          EMAIL_REPO: 'index=email'
        },
        validation: {
          required_fields: ['_time', 'host', 'source'],
          notes: ['Ensure Common Information Model (CIM) is configured', 'Index names may vary by environment']
        }
      },
      {
        id: 'splunk-cloud',
        name: 'Splunk Cloud',
        description: 'Splunk Cloud Platform with enhanced security data models',
        fields: {
          DST_IP_FIELD: 'dest_ip',
          SRC_IP_FIELD: 'src_ip',
          DOMAIN_FIELD: 'dns_query',
          URL_FIELD: 'url',
          HOST_FIELD: 'dest_host',
          USERNAME_FIELD: 'user',
          PROC_PATH_FIELD: 'process_name',
          SHA256_FIELD: 'file_hash',
          MD5_FIELD: 'file_hash',
          EMAIL_FIELD: 'recipient',
          ACTION_FIELD: 'action'
        },
        repos: {
          PROXY_REPO: 'index=web',
          DNS_REPO: 'index=network',
          EDR_REPO: 'index=endpoint',
          IDP_REPO: 'index=security',
          EMAIL_REPO: 'index=email'
        },
        validation: {
          required_fields: ['_time', 'host', 'sourcetype'],
          notes: ['Splunk Cloud Platform optimized', 'Security Essentials app recommended']
        }
      },
      {
        id: 'splunk-syslog',
        name: 'Splunk Raw/Syslog',
        description: 'Raw syslog and unstructured data ingestion',
        fields: {
          DST_IP_FIELD: 'dest_ip',
          SRC_IP_FIELD: 'src_ip',
          DOMAIN_FIELD: 'domain',
          URL_FIELD: 'url',
          HOST_FIELD: 'host',
          USERNAME_FIELD: 'user',
          PROC_PATH_FIELD: 'process',
          SHA256_FIELD: 'hash',
          MD5_FIELD: 'hash',
          EMAIL_FIELD: 'email',
          ACTION_FIELD: 'action'
        },
        repos: {
          PROXY_REPO: 'sourcetype=access_combined',
          DNS_REPO: 'sourcetype=named',
          EDR_REPO: 'sourcetype=syslog',
          IDP_REPO: 'sourcetype=linux_secure',
          EMAIL_REPO: 'sourcetype=sendmail'
        },
        validation: {
          required_fields: ['_time', '_raw'],
          notes: ['Raw data parsing - field extraction may be limited', 'Configure field extractions for better results']
        }
      }
    ]
  },
  {
    id: 'sentinel',
    name: 'Microsoft Sentinel',
    description: 'Microsoft Sentinel with Kusto Query Language (KQL)',
    documentation_url: 'https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/',
    modules: [
      {
        id: 'sentinel-standard',
        name: 'Microsoft Sentinel Standard',
        description: 'Standard Microsoft Sentinel with Common Event Format (CEF)',
        fields: {
          DST_IP_FIELD: 'DstIpAddr',
          SRC_IP_FIELD: 'SrcIpAddr',
          DOMAIN_FIELD: 'DnsQuery',
          URL_FIELD: 'Url',
          HOST_FIELD: 'Computer',
          USERNAME_FIELD: 'AccountName',
          PROC_PATH_FIELD: 'ProcessName',
          SHA256_FIELD: 'SHA256',
          MD5_FIELD: 'MD5',
          EMAIL_FIELD: 'RecipientEmailAddress',
          ACTION_FIELD: 'Activity'
        },
        repos: {
          PROXY_REPO: 'CommonSecurityLog',
          DNS_REPO: 'DnsEvents',
          EDR_REPO: 'SecurityEvent',
          IDP_REPO: 'SigninLogs',
          EMAIL_REPO: 'EmailEvents'
        },
        validation: {
          required_fields: ['TimeGenerated', 'Computer'],
          notes: ['Azure Log Analytics workspace required', 'Data connectors must be configured']
        }
      },
      {
        id: 'sentinel-defender',
        name: 'Sentinel + Defender',
        description: 'Microsoft Sentinel with Defender for Endpoint integration',
        fields: {
          DST_IP_FIELD: 'RemoteIP',
          SRC_IP_FIELD: 'LocalIP',
          DOMAIN_FIELD: 'RemoteUrl',
          URL_FIELD: 'RemoteUrl',
          HOST_FIELD: 'DeviceName',
          USERNAME_FIELD: 'AccountName',
          PROC_PATH_FIELD: 'FolderPath',
          SHA256_FIELD: 'SHA256',
          MD5_FIELD: 'MD5',
          EMAIL_FIELD: 'SenderFromAddress',
          ACTION_FIELD: 'ActionType'
        },
        repos: {
          PROXY_REPO: 'DeviceNetworkEvents',
          DNS_REPO: 'DeviceNetworkEvents',
          EDR_REPO: 'DeviceProcessEvents',
          IDP_REPO: 'DeviceLogonEvents',
          EMAIL_REPO: 'EmailEvents'
        },
        validation: {
          required_fields: ['Timestamp', 'DeviceName'],
          notes: ['Microsoft Defender for Endpoint required', 'Advanced hunting tables available']
        }
      }
    ]
  },
  {
    id: 'custom',
    name: 'Custom/Generic',
    description: 'Custom field mappings for other SIEM platforms or data sources',
    modules: [
      {
        id: 'custom-generic',
        name: 'Generic Fields',
        description: 'Generic field mappings - customize for your environment',
        fields: {
          DST_IP_FIELD: 'destination_ip',
          SRC_IP_FIELD: 'source_ip',
          DOMAIN_FIELD: 'domain_name',
          URL_FIELD: 'url',
          HOST_FIELD: 'hostname',
          USERNAME_FIELD: 'user',
          PROC_PATH_FIELD: 'process_path',
          SHA256_FIELD: 'hash_sha256',
          MD5_FIELD: 'hash_md5',
          EMAIL_FIELD: 'email_address',
          ACTION_FIELD: 'event_action'
        },
        repos: {
          PROXY_REPO: 'index=proxy',
          DNS_REPO: 'index=dns', 
          EDR_REPO: 'index=endpoint',
          IDP_REPO: 'index=identity',
          EMAIL_REPO: 'index=email'
        },
        validation: {
          required_fields: ['timestamp', 'hostname'],
          notes: ['Customize field mappings for your environment', 'Generic mappings - may need adjustment']
        }
      }
    ]
  },
  // Phase 2: Additional SIEM platforms
  {
    id: 'elastic',
    name: 'Elastic Security',
    description: 'Elasticsearch-based SIEM with ES|QL support',
    queryLanguage: 'ES|QL',
    documentation_url: 'https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html',
    modules: [
      {
        id: 'elastic-security',
        name: 'Elastic Security',
        description: 'Standard Elastic Security deployment',
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
          EMAIL_FIELD: 'email.from.address',
          ACTION_FIELD: 'event.action'
        },
        repos: {
          PROXY_REPO: 'FROM logs-*',
          DNS_REPO: 'FROM logs-dns-*',
          EDR_REPO: 'FROM logs-endpoint-*',
          IDP_REPO: 'FROM logs-auth-*',
          EMAIL_REPO: 'FROM logs-email-*'
        },
        validation: {
          required_fields: ['@timestamp', 'host.name'],
          notes: [
            'ES|QL queries require FROM clause',
            'Use ECS field naming conventions',
            'Supports aggregations and transformations'
          ]
        }
      }
    ]
  },
  {
    id: 'qradar',
    name: 'IBM QRadar',
    description: 'IBM QRadar SIEM with AQL support',
    queryLanguage: 'AQL',
    documentation_url: 'https://www.ibm.com/docs/en/qradar-common',
    modules: [
      {
        id: 'qradar-standard',
        name: 'QRadar Standard',
        description: 'Standard IBM QRadar deployment',
        fields: {
          DST_IP_FIELD: 'destinationip',
          SRC_IP_FIELD: 'sourceip',
          DOMAIN_FIELD: 'domainname',
          URL_FIELD: 'url',
          HOST_FIELD: 'hostname',
          USERNAME_FIELD: 'username',
          PROC_PATH_FIELD: 'filepath',
          SHA256_FIELD: 'sha256hash',
          MD5_FIELD: 'md5hash',
          EMAIL_FIELD: 'emailaddress',
          ACTION_FIELD: 'eventname'
        },
        repos: {
          PROXY_REPO: 'SELECT * FROM events WHERE category = 6',
          DNS_REPO: 'SELECT * FROM events WHERE category = 15',
          EDR_REPO: 'SELECT * FROM events WHERE category = 4',
          IDP_REPO: 'SELECT * FROM events WHERE category = 3',
          EMAIL_REPO: 'SELECT * FROM events WHERE category = 25'
        },
        validation: {
          required_fields: ['starttime', 'sourceip'],
          notes: [
            'AQL uses SQL-like syntax',
            'Category numbers identify log types',
            'Time ranges use LAST X HOURS format'
          ]
        }
      }
    ]
  },
  {
    id: 'chronicle',
    name: 'Google Chronicle',
    description: 'Google Chronicle SIEM with UDM support',
    queryLanguage: 'UDM Search',
    documentation_url: 'https://cloud.google.com/chronicle/docs',
    modules: [
      {
        id: 'chronicle-standard',
        name: 'Chronicle Standard',
        description: 'Standard Google Chronicle deployment',
        fields: {
          DST_IP_FIELD: 'target.ip',
          SRC_IP_FIELD: 'principal.ip',
          DOMAIN_FIELD: 'network.dns.questions.name',
          URL_FIELD: 'target.url',
          HOST_FIELD: 'target.hostname',
          USERNAME_FIELD: 'principal.user.userid',
          PROC_PATH_FIELD: 'target.process.file.full_path',
          SHA256_FIELD: 'target.file.sha256',
          MD5_FIELD: 'target.file.md5',
          EMAIL_FIELD: 'network.email.from',
          ACTION_FIELD: 'metadata.event_type'
        },
        repos: {
          PROXY_REPO: 'metadata.event_type = "NETWORK_HTTP"',
          DNS_REPO: 'metadata.event_type = "NETWORK_DNS"',
          EDR_REPO: 'metadata.event_type = "PROCESS_LAUNCH"',
          IDP_REPO: 'metadata.event_type = "USER_LOGIN"',
          EMAIL_REPO: 'metadata.event_type = "EMAIL_TRANSACTION"'
        },
        validation: {
          required_fields: ['metadata.event_timestamp', 'metadata.event_type'],
          notes: [
            'UDM uses structured data model',
            'Event types define data categories',
            'Supports complex nested queries'
          ]
        }
      }
    ]
  }
];

export const getVendorById = (vendorId: string): Vendor | undefined => {
  return vendors.find(v => v.id === vendorId);
};

export const getModuleById = (vendorId: string, moduleId: string): VendorModule | undefined => {
  const vendor = getVendorById(vendorId);
  return vendor?.modules.find(m => m.id === moduleId);
};

export const validateFieldMapping = (vendorId: string, moduleId: string, requiredFields: string[]): {
  valid: boolean;
  missing: string[];
  warnings: string[];
} => {
  const module = getModuleById(vendorId, moduleId);
  if (!module) {
    return { valid: false, missing: requiredFields, warnings: ['Module not found'] };
  }

  const availableFields = Object.keys(module.fields);
  const missing = requiredFields.filter(field => !availableFields.includes(field));
  const warnings: string[] = [];

  // Add CPS-specific warnings
  if (vendorId === 'crowdstrike' && module.validation?.cps_modules) {
    warnings.push('Ensure CPS modules are enabled: ' + module.validation.cps_modules.join(', '));
  }

  if (module.validation?.notes) {
    warnings.push(...module.validation.notes);
  }

  return {
    valid: missing.length === 0,
    missing,
    warnings
  };
};