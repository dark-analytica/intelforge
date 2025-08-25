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
}

export const vendors: Vendor[] = [
  {
    id: 'crowdstrike',
    name: 'CrowdStrike NG-SIEM',
    description: 'CrowdStrike Next-Gen SIEM with CPS (CrowdStrike Platform Standard) field mappings',
    documentation_url: 'https://docs.crowdstrike.com/cps/',
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
    name: 'CrowdStrike LogScale (Humio)', 
    description: 'LogScale platform with standard log parsing and field extraction',
    documentation_url: 'https://library.humio.com/',
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