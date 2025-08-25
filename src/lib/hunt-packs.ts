// TTP-First Hunt Packs - Pre-built hunt templates organized by MITRE ATT&CK tactics

export interface HuntPack {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  techniques: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  queries: HuntQuery[];
  metadata: {
    threat_actors?: string[];
    industries?: string[];
    platforms?: string[];
    last_updated: string;
  };
}

export interface HuntQuery {
  id: string;
  name: string;
  description: string;
  query: string;
  data_sources: string[];
  confidence: 'high' | 'medium' | 'low';
  techniques: string[];
}

export const huntPacks: HuntPack[] = [
  {
    id: 'initial-access-web',
    name: 'Initial Access via Web Applications',
    description: 'Comprehensive hunt pack for detecting initial access through web application exploitation',
    tactics: ['Initial Access', 'Execution'],
    techniques: ['T1190', 'T1505.003', 'T1059.007'],
    difficulty: 'intermediate',
    queries: [
      {
        id: 'web-shell-detection',
        name: 'Web Shell Activity Detection',
        description: 'Detect potential web shell deployments and execution',
        query: `(sourcetype="iis:*" OR sourcetype="apache:*" OR sourcetype="nginx:*")
AND (cs_uri_stem=*.aspx OR cs_uri_stem=*.asp OR cs_uri_stem=*.php OR cs_uri_stem=*.jsp)
AND (cs_uri_query=*cmd* OR cs_uri_query=*exec* OR cs_uri_query=*eval*)
AND @timestamp >= now()-24h
| eval suspicious_params = if(match(cs_uri_query, "(cmd|exec|eval|system|shell)"), "true", "false")
| where suspicious_params="true"
| stats count() as hits, values(cs_uri_query) as queries by src_ip, cs_uri_stem
| where hits > 5
| sort -hits`,
        data_sources: ['Web Server Logs', 'IIS Logs', 'Apache Logs'],
        confidence: 'high',
        techniques: ['T1505.003']
      },
      {
        id: 'exploit-attempts',
        name: 'Web Application Exploit Attempts',
        description: 'Detect common web application exploit patterns',
        query: `(sourcetype="web:*" OR event_simpleName=NetworkConnect*)
AND (cs_uri_query=*union* OR cs_uri_query=*select* OR cs_uri_query=*drop* OR cs_uri_query=*<script>* OR cs_uri_query=*../../*)
AND @timestamp >= now()-24h
| eval attack_type = case(
    match(cs_uri_query, "union|select|drop"), "SQL Injection",
    match(cs_uri_query, "<script|javascript"), "XSS",
    match(cs_uri_query, "\.\./"), "Directory Traversal",
    "Other"
)
| stats count() as attempts by src_ip, attack_type, cs_host
| where attempts > 3
| sort -attempts`,
        data_sources: ['Web Application Firewalls', 'Proxy Logs'],
        confidence: 'medium',
        techniques: ['T1190']
      }
    ],
    metadata: {
      threat_actors: ['APT28', 'Lazarus Group', 'FIN7'],
      industries: ['Financial', 'Healthcare', 'Government'],
      platforms: ['Windows', 'Linux'],
      last_updated: '2025-01-25'
    }
  },
  {
    id: 'persistence-registry',
    name: 'Registry-Based Persistence',
    description: 'Hunt for persistence mechanisms using Windows Registry modifications',
    tactics: ['Persistence', 'Privilege Escalation'],
    techniques: ['T1547.001', 'T1112', 'T1546.003'],
    difficulty: 'beginner',
    queries: [
      {
        id: 'autostart-registry',
        name: 'Autostart Registry Modifications',
        description: 'Detect modifications to autostart registry locations',
        query: `sourcetype="windows:registry:*" OR event_simpleName=ProcessRollup*
AND (RegistryPath=*Run* OR RegistryPath=*RunOnce* OR RegistryPath=*Winlogon* OR RegistryPath=*userinit*)
AND EventType="SetValue"
AND @timestamp >= now()-24h
| eval persistence_location = case(
    match(RegistryPath, "Run$"), "HKLM/HKCU Run",
    match(RegistryPath, "RunOnce"), "RunOnce",
    match(RegistryPath, "Winlogon"), "Winlogon",
    match(RegistryPath, "userinit"), "Userinit",
    "Other"
)
| stats count() as modifications, values(RegistryValue) as values by ComputerName, UserName, persistence_location
| sort -modifications`,
        data_sources: ['Windows Registry Events', 'Endpoint Detection'],
        confidence: 'high',
        techniques: ['T1547.001']
      },
      {
        id: 'wmi-persistence',
        name: 'WMI Event Subscription Persistence',
        description: 'Detect WMI event subscription persistence mechanisms',
        query: `sourcetype="windows:wmi:*" OR event_simpleName=WmiCreateProcess*
AND (EventType="WmiEventFilter" OR EventType="WmiEventConsumer" OR EventType="WmiFilterToConsumerBinding")
AND @timestamp >= now()-24h
| eval wmi_component = case(
    EventType="WmiEventFilter", "Event Filter",
    EventType="WmiEventConsumer", "Event Consumer",
    EventType="WmiFilterToConsumerBinding", "Filter Binding",
    "Unknown"
)
| stats count() as events by ComputerName, UserName, wmi_component, QueryText
| sort -events`,
        data_sources: ['WMI Events', 'Endpoint Detection'],
        confidence: 'high',
        techniques: ['T1546.003']
      }
    ],
    metadata: {
      threat_actors: ['APT29', 'Carbanak', 'Turla'],
      industries: ['All'],
      platforms: ['Windows'],
      last_updated: '2025-01-25'
    }
  },
  {
    id: 'lateral-movement-smb',
    name: 'SMB-Based Lateral Movement',
    description: 'Advanced hunt pack for detecting lateral movement via SMB and administrative shares',
    tactics: ['Lateral Movement', 'Execution'],
    techniques: ['T1021.002', 'T1570', 'T1135'],
    difficulty: 'advanced',
    queries: [
      {
        id: 'admin-share-access',
        name: 'Administrative Share Access Patterns',
        description: 'Detect suspicious access to administrative shares across multiple hosts',
        query: `sourcetype="windows:security:*" OR event_simpleName=NetworkConnect*
AND (EventCode=5140 OR EventCode=5145)
AND (ShareName=*C$* OR ShareName=*ADMIN$* OR ShareName=*IPC$*)
AND @timestamp >= now()-24h
| eval share_type = case(
    match(ShareName, "C\\$"), "Drive Share",
    match(ShareName, "ADMIN\\$"), "Admin Share",
    match(ShareName, "IPC\\$"), "IPC Share",
    "Other"
)
| stats count() as accesses, dc(Computer) as unique_targets by SubjectUserName, src_ip, share_type
| where unique_targets > 3 OR accesses > 20
| sort -unique_targets, -accesses`,
        data_sources: ['Windows Security Events', 'Network Detection'],
        confidence: 'high',
        techniques: ['T1021.002']
      },
      {
        id: 'psexec-activity',
        name: 'PsExec-Style Remote Execution',
        description: 'Detect PsExec and similar remote execution patterns',
        query: `sourcetype="windows:*" OR event_simpleName=ProcessRollup*
AND (ProcessName=*psexec* OR ServiceName=*PSEXESVC* OR ProcessName=*paexec* OR ProcessName=*wmiexec*)
AND @timestamp >= now()-24h
| eval execution_tool = case(
    match(ProcessName, "psexec"), "PsExec",
    match(ServiceName, "PSEXESVC"), "PsExec Service",
    match(ProcessName, "paexec"), "PAExec",
    match(ProcessName, "wmiexec"), "WMIExec",
    "Other"
)
| stats count() as executions, dc(ComputerName) as target_hosts by UserName, ParentProcessName, execution_tool
| where target_hosts > 1
| sort -target_hosts, -executions`,
        data_sources: ['Process Events', 'Service Events'],
        confidence: 'high',
        techniques: ['T1570']
      }
    ],
    metadata: {
      threat_actors: ['APT1', 'Conti', 'Ryuk'],
      industries: ['Enterprise', 'Government'],
      platforms: ['Windows'],
      last_updated: '2025-01-25'
    }
  },
  {
    id: 'credential-access-dump',
    name: 'Credential Dumping Detection',
    description: 'Comprehensive detection of credential dumping techniques',
    tactics: ['Credential Access', 'Defense Evasion'],
    techniques: ['T1003.001', 'T1003.002', 'T1003.003'],
    difficulty: 'advanced',
    queries: [
      {
        id: 'lsass-access',
        name: 'LSASS Process Access',
        description: 'Detect suspicious access to LSASS process for credential dumping',
        query: `sourcetype="windows:security:*" OR event_simpleName=ProcessRollup*
AND (TargetProcessName=*lsass.exe* OR ProcessName=*lsass.exe*)
AND (EventCode=4656 OR event_simpleName=ProcessAccess*)
AND AccessMask!="0x1400"
AND @timestamp >= now()-24h
| eval access_type = case(
    match(AccessMask, "0x1010"), "Read/Query",
    match(AccessMask, "0x1038"), "Read/VM Read",
    match(AccessMask, "0x1fffff"), "Full Access",
    "Other (" + AccessMask + ")"
)
| stats count() as accesses by SubjectProcessName, SubjectUserName, ComputerName, access_type
| where accesses > 1
| sort -accesses`,
        data_sources: ['Windows Security Events', 'Process Monitoring'],
        confidence: 'high',
        techniques: ['T1003.001']
      },
      {
        id: 'sam-registry-access',
        name: 'SAM Registry Hive Access',
        description: 'Detect attempts to access SAM registry hive for credential extraction',
        query: `sourcetype="windows:registry:*" OR event_simpleName=ProcessRollup*
AND (RegistryPath=*SAM\\SAM\\Domains* OR RegistryPath=*SECURITY\\Policy\\Secrets*)
AND EventType="QueryValue"
AND @timestamp >= now()-24h
| stats count() as queries, values(RegistryPath) as paths by ComputerName, ProcessName, UserName
| where queries > 5
| sort -queries`,
        data_sources: ['Registry Events', 'Endpoint Detection'],
        confidence: 'high',
        techniques: ['T1003.002']
      }
    ],
    metadata: {
      threat_actors: ['Mimikatz Users', 'APT28', 'Lazarus Group'],
      industries: ['All'],
      platforms: ['Windows'],
      last_updated: '2025-01-25'
    }
  }
];

export const getHuntPacksByTactic = (tactic: string): HuntPack[] => {
  return huntPacks.filter(pack => pack.tactics.includes(tactic));
};

export const getHuntPacksByTechnique = (technique: string): HuntPack[] => {
  return huntPacks.filter(pack => pack.techniques.includes(technique));
};

export const getHuntPacksByDifficulty = (difficulty: 'beginner' | 'intermediate' | 'advanced'): HuntPack[] => {
  return huntPacks.filter(pack => pack.difficulty === difficulty);
};

export const searchHuntPacks = (query: string): HuntPack[] => {
  const searchTerm = query.toLowerCase();
  return huntPacks.filter(pack => 
    pack.name.toLowerCase().includes(searchTerm) ||
    pack.description.toLowerCase().includes(searchTerm) ||
    pack.tactics.some(tactic => tactic.toLowerCase().includes(searchTerm)) ||
    pack.techniques.some(technique => technique.toLowerCase().includes(searchTerm)) ||
    pack.metadata.threat_actors?.some(actor => actor.toLowerCase().includes(searchTerm))
  );
};