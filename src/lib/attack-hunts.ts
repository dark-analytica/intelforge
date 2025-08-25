export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  tactic: string;
}

export interface HuntIdea {
  id: string;
  title: string;
  description: string;
  techniques: string[];
  template: string;
  repo: string;
  confidence: 'high' | 'medium' | 'low';
}

export const attackTechniques: Record<string, AttackTechnique> = {
  'T1190': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program',
    tactic: 'Initial Access'
  },
  'T1071.001': {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    description: 'Adversaries may communicate using application layer protocols associated with web traffic',
    tactic: 'Command and Control'
  },
  'T1059.001': {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution',
    tactic: 'Execution'
  },
  'T1055': {
    id: 'T1055',
    name: 'Process Injection',
    description: 'Adversaries may inject code into processes in order to evade process-based defenses',
    tactic: 'Defense Evasion'
  },
  'T1083': {
    id: 'T1083',
    name: 'File and Directory Discovery',
    description: 'Adversaries may enumerate files and directories or may search in specific locations',
    tactic: 'Discovery'
  }
};

export const generateHuntIdeas = (iocs: { [key: string]: string[] }, ttps?: any[]): HuntIdea[] => {
  const ideas: HuntIdea[] = [];
  
  // TTP-based hunts (highest priority in Pyramid of Pain)
  if (ttps && ttps.length > 0) {
    ttps.forEach(ttp => {
      if (ttp.technique_id) {
        // Generate technique-specific hunts
        const techniqueHunt = getTechniqueSpecificHunt(ttp);
        if (techniqueHunt) {
          ideas.push(techniqueHunt);
        }
        
        // Generate tactic-based correlation hunts
        if (ttp.tactic) {
          const tacticHunt = getTacticCorrelationHunt(ttp, ttps);
          if (tacticHunt) {
            ideas.push(tacticHunt);
          }
        }
      }
    });
  }
  
  // Advanced IOC correlation hunts
  const correlationHunts = generateCorrelationHunts(iocs);
  ideas.push(...correlationHunts);
  
  // IP-based hunts with enhanced detection
  if (iocs.ips?.length > 0 || iocs.ipv4?.length > 0 || iocs.ipv6?.length > 0) {
    ideas.push({
      id: 'ip-advanced-c2',
      title: 'Advanced C2 Infrastructure Hunt',
      description: 'Multi-stage hunt for command and control patterns using behavioral analysis',
      techniques: ['T1071.001', 'T1090.003'],
      template: 'ip-advanced-c2-hunt',
      repo: 'all',
      confidence: 'high'
    });
    
    ideas.push({
      id: 'ip-beaconing-detection',
      title: 'Network Beaconing Detection',
      description: 'Detect periodic communication patterns indicating C2 beaconing',
      techniques: ['T1071.001'],
      template: 'ip-beaconing-hunt',
      repo: 'proxy',
      confidence: 'medium'
    });
  }
  
  // Domain-based advanced hunts
  if (iocs.domains?.length > 0) {
    ideas.push({
      id: 'domain-dga-detection',
      title: 'Domain Generation Algorithm Detection',
      description: 'Hunt for algorithmically generated domains using entropy analysis',
      techniques: ['T1071.004', 'T1568.002'],
      template: 'domain-dga-hunt',
      repo: 'dns',
      confidence: 'medium'
    });
    
    ideas.push({
      id: 'domain-typosquatting',
      title: 'Typosquatting Domain Hunt',
      description: 'Detect typosquatting domains targeting legitimate services',
      techniques: ['T1566.002'],
      template: 'domain-typo-hunt',
      repo: 'dns',
      confidence: 'high'
    });
  }
  
  // Hash-based behavioral hunts
  if (iocs.hashes?.length > 0 || iocs.sha256?.length > 0 || iocs.md5?.length > 0) {
    ideas.push({
      id: 'malware-family-clustering',
      title: 'Malware Family Clustering',
      description: 'Group and analyze malware samples for family attribution',
      techniques: ['T1059.001', 'T1055'],
      template: 'hash-family-hunt',
      repo: 'edr',
      confidence: 'high'
    });
    
    ideas.push({
      id: 'persistence-correlation',
      title: 'Malware Persistence Correlation',
      description: 'Correlate file presence with persistence mechanisms',
      techniques: ['T1547.001', 'T1543.003'],
      template: 'hash-persistence-hunt',
      repo: 'edr',
      confidence: 'medium'
    });
  }
  
  // Email-based advanced hunts
  if (iocs.emails?.length > 0) {
    ideas.push({
      id: 'email-campaign-analysis',
      title: 'Email Campaign Analysis',
      description: 'Analyze email patterns for campaign attribution and targeting',
      techniques: ['T1566.001', 'T1598.003'],
      template: 'email-campaign-hunt',
      repo: 'email',
      confidence: 'high'
    });
  }
  
  return ideas;
};

// Helper functions for advanced hunt generation
const getTechniqueSpecificHunt = (ttp: any): HuntIdea | null => {
  const techniqueHunts: Record<string, Partial<HuntIdea>> = {
    'T1059.001': {
      title: 'PowerShell Execution Analysis',
      description: 'Deep analysis of PowerShell usage patterns and suspicious behaviors',
      template: 'powershell-behavior-hunt'
    },
    'T1055': {
      title: 'Process Injection Detection',
      description: 'Hunt for various process injection techniques and evasion methods',
      template: 'process-injection-hunt'
    },
    'T1083': {
      title: 'File Discovery Enumeration',
      description: 'Detect systematic file and directory enumeration activities',
      template: 'file-discovery-hunt'
    },
    'T1071.001': {
      title: 'Web Protocol C2 Analysis',
      description: 'Analyze web traffic for command and control communications',
      template: 'web-c2-hunt'
    }
  };

  const hunt = techniqueHunts[ttp.technique_id];
  if (!hunt) return null;

  return {
    id: `ttp-${ttp.technique_id}`,
    title: hunt.title || `${ttp.technique_id} Hunt`,
    description: hunt.description || `Hunt for ${ttp.behavior || 'behaviors'} based on extracted TTPs`,
    techniques: [ttp.technique_id],
    template: hunt.template || 'ttp-generic-hunt',
    repo: 'all',
    confidence: 'high'
  };
};

const getTacticCorrelationHunt = (ttp: any, allTtps: any[]): HuntIdea | null => {
  const sameTacticTtps = allTtps.filter(t => t.tactic === ttp.tactic && t.technique_id !== ttp.technique_id);
  
  if (sameTacticTtps.length === 0) return null;

  // Create unique ID using tactic and technique combination to avoid duplicates
  const tacticSlug = ttp.tactic.toLowerCase().replace(/\s+/g, '-');
  const techniqueSlug = ttp.technique_id.replace('.', '-');

  return {
    id: `tactic-correlation-${tacticSlug}-${techniqueSlug}`,
    title: `${ttp.tactic} Tactic Correlation`,
    description: `Correlate multiple techniques within ${ttp.tactic} tactic for campaign analysis`,
    techniques: [ttp.technique_id, ...sameTacticTtps.map(t => t.technique_id)],
    template: 'tactic-correlation-hunt',
    repo: 'all',
    confidence: 'medium'
  };
};

const generateCorrelationHunts = (iocs: { [key: string]: string[] }): HuntIdea[] => {
  const hunts: HuntIdea[] = [];
  
  // Multi-IOC correlation hunt
  const iocTypes = Object.keys(iocs).filter(key => iocs[key]?.length > 0);
  if (iocTypes.length >= 2) {
    hunts.push({
      id: 'multi-ioc-correlation',
      title: 'Multi-IOC Correlation Analysis',
      description: `Cross-reference ${iocTypes.join(', ')} for campaign attribution`,
      techniques: ['T1071.001', 'T1090', 'T1566'],
      template: 'multi-ioc-correlation-hunt',
      repo: 'all',
      confidence: 'high'
    });
  }
  
  // Temporal correlation hunt
  if (iocTypes.length > 0) {
    hunts.push({
      id: 'temporal-correlation',
      title: 'Temporal IOC Correlation',
      description: 'Analyze timing patterns across different IOC types for attack timeline',
      techniques: ['T1071', 'T1566'],
      template: 'temporal-correlation-hunt',
      repo: 'all',
      confidence: 'medium'
    });
  }
  
  return hunts;
};

export const getHuntTemplate = (huntId: string, iocs: { [key: string]: string[] }): string => {
  // Get all IP addresses from different fields
  const allIps = [
    ...(iocs.ips || []),
    ...(iocs.ipv4 || []),
    ...(iocs.ipv6 || [])
  ];
  
  // Get all hashes from different fields
  const allHashes = [
    ...(iocs.hashes || []),
    ...(iocs.sha256 || []),
    ...(iocs.md5 || [])
  ];

  switch (huntId) {
    case 'ip-advanced-c2':
      return `// Advanced C2 Infrastructure Hunt
(sourcetype="proxy:*" OR sourcetype="firewall:*" OR event_simpleName=NetworkConnect*)
AND dst_ip IN [${allIps.map(ip => `"${ip}"`).join(', ')}]
AND @timestamp >= now()-7d
| eval connection_type = case(
    match(sourcetype, "proxy"), "Web Traffic",
    match(sourcetype, "firewall"), "Network",
    match(event_simpleName, "NetworkConnect"), "Endpoint",
    "Other"
)
| bucket span=1h _time=@timestamp
| stats count() as connections, dc(src_ip) as unique_sources, sum(bytes_out) as total_bytes by _time, dst_ip, connection_type
| eval suspicious_score = case(
    unique_sources > 10 AND total_bytes > 10000, 3,
    unique_sources > 5 OR total_bytes > 50000, 2,
    1
)
| where suspicious_score >= 2
| sort -_time, -suspicious_score`;

    case 'ip-beaconing-detection':
      return `// Network Beaconing Detection
sourcetype="proxy:*" OR event_simpleName=NetworkConnect*
AND dst_ip IN [${allIps.map(ip => `"${ip}"`).join(', ')}]
AND @timestamp >= now()-24h
| bucket span=10m _time=@timestamp
| stats count() as requests, avg(bytes_out) as avg_bytes by _time, src_ip, dst_ip
| sort src_ip, dst_ip, _time
| eval time_diff = _time - lag(_time, 1) by src_ip, dst_ip
| where time_diff > 0
| stats avg(time_diff) as avg_interval, stdev(time_diff) as interval_stdev, count() as total_requests by src_ip, dst_ip
| eval beacon_score = case(
    interval_stdev < (avg_interval * 0.1) AND total_requests > 10, 3,
    interval_stdev < (avg_interval * 0.3) AND total_requests > 5, 2,
    1
)
| where beacon_score >= 2
| sort -beacon_score`;

    case 'domain-dga-detection':
      return `// Domain Generation Algorithm Detection
sourcetype="dns:*" OR event_simpleName=DnsRequest*
AND domain IN [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}]
AND @timestamp >= now()-24h
| eval domain_entropy = entropy(domain)
| eval domain_length = len(domain)
| eval vowel_consonant_ratio = (len(replace(domain, "[^aeiou]", "")) / len(replace(domain, "[aeiou]", "")))
| eval char_frequency_score = entropy(split(domain, ""))
| eval dga_score = case(
    domain_entropy > 4.5 AND domain_length > 15 AND vowel_consonant_ratio < 0.3, 3,
    domain_entropy > 4.0 AND (domain_length > 12 OR vowel_consonant_ratio < 0.4), 2,
    domain_entropy > 3.5, 1,
    0
)
| where dga_score >= 2
| stats count() as queries, values(src_ip) as sources by domain, dga_score
| sort -dga_score, -queries`;

    case 'hash-family-hunt':
      return `// Malware Family Clustering Hunt
sourcetype="edr:*" OR event_simpleName=ProcessRollup*
AND (sha256 IN [${allHashes.filter(h => h.length === 64).map(h => `"${h}"`).join(', ')}] OR md5 IN [${allHashes.filter(h => h.length === 32).map(h => `"${h}"`).join(', ')}])
AND @timestamp >= now()-30d
| eval hash_type = if(len(coalesce(sha256, md5)) == 64, "SHA256", "MD5")
| eval file_hash = coalesce(sha256, md5)
| stats count() as executions, 
        dc(ComputerName) as unique_hosts,
        values(ProcessName) as process_names,
        values(CommandLine) as command_lines,
        values(ParentProcessName) as parent_processes,
        min(@timestamp) as first_seen,
        max(@timestamp) as last_seen
        by file_hash, hash_type
| eval campaign_indicator = case(
    unique_hosts > 10, "Widespread Campaign",
    unique_hosts > 3, "Targeted Campaign",
    "Limited Deployment"
)
| sort -unique_hosts, -executions`;

    case 'multi-ioc-correlation-hunt':
      return `// Multi-IOC Correlation Analysis
(sourcetype="*" OR event_simpleName=*)
AND (@timestamp >= now()-7d)
AND (
    dst_ip IN [${allIps.map(ip => `"${ip}"`).join(', ')}] OR
    domain IN [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}] OR
    sha256 IN [${allHashes.filter(h => h.length === 64).map(h => `"${h}"`).join(', ')}] OR
    email IN [${iocs.emails?.map(e => `"${e}"`).join(', ') || ''}]
)
| eval ioc_type = case(
    isnotnull(dst_ip) AND dst_ip IN [${allIps.map(ip => `"${ip}"`).join(', ')}], "IP",
    isnotnull(domain) AND domain IN [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}], "Domain",
    isnotnull(sha256) AND sha256 IN [${allHashes.filter(h => h.length === 64).map(h => `"${h}"`).join(', ')}], "Hash",
    isnotnull(email) AND email IN [${iocs.emails?.map(e => `"${e}"`).join(', ') || ''}], "Email",
    "Unknown"
)
| eval ioc_value = coalesce(dst_ip, domain, sha256, email)
| bucket span=1h _time=@timestamp
| stats count() as events, 
        dc(ioc_type) as ioc_types,
        values(ioc_type) as types_seen,
        dc(src_ip) as unique_sources
        by _time, ComputerName
| where ioc_types >= 2
| sort -_time, -ioc_types`;

    case 'temporal-correlation-hunt':
      return `// Temporal IOC Correlation Hunt
(sourcetype="*" OR event_simpleName=*)
AND (@timestamp >= now()-24h)
AND (
    dst_ip IN [${allIps.map(ip => `"${ip}"`).join(', ')}] OR
    domain IN [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}] OR
    sha256 IN [${allHashes.filter(h => h.length === 64).map(h => `"${h}"`).join(', ')}]
)
| eval ioc_type = case(
    isnotnull(dst_ip) AND dst_ip IN [${allIps.map(ip => `"${ip}"`).join(', ')}], "Network",
    isnotnull(domain) AND domain IN [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}], "DNS",
    isnotnull(sha256), "File",
    "Other"
)
| bucket span=5m _time=@timestamp
| stats count() as events by _time, ioc_type, ComputerName
| sort _time, ComputerName
| eval next_time = lead(_time, 1) by ComputerName
| eval time_diff = (next_time - _time) / 60
| where time_diff <= 30
| stats count() as correlated_events, min(time_diff) as min_gap by ComputerName, ioc_type
| where correlated_events > 1
| sort -correlated_events`;
      
    default:
      // Handle TTP-based hunts and other templates
      if (huntId.startsWith('ttp-')) {
        const techniqueId = huntId.replace('ttp-', '');
        return `// TTP-Based Hunt: ${techniqueId}
sourcetype="*" OR event_simpleName=*
AND @timestamp >= now()-24h
| where match(lower(coalesce(CommandLine, ProcessName, event_message, "")), "${techniqueId.toLowerCase()}|technique|tactic")
| eval detection_confidence = case(
    match(CommandLine, "(?i)(powershell|cmd|wmic|rundll32)"), 3,
    match(ProcessName, "(?i)(suspicious|malware|trojan)"), 2,
    1
)
| stats count() as events, 
        values(CommandLine) as commands,
        values(ProcessName) as processes
        by ComputerName, UserName, detection_confidence
| where detection_confidence >= 2 OR events > 5
| sort -detection_confidence, -events`;
      }
      
      // Legacy hunt templates for backward compatibility
      if (huntId === 'ip-c2-hunt') {
        return `#type=proxy
| in(dst_ip, [${allIps.map(ip => `"${ip}"`).join(', ')}])
| stats dc(src_ip) as unique_sources by dst_ip
| where unique_sources > 1
| sort(unique_sources, desc)`;
      }
      
      if (huntId === 'domain-c2-hunt' || huntId === 'domain-dns-hunt') {
        return `#type=dns OR #type=proxy
| in(domain, [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}])
| timechart(span=1h, by=domain)
| sort(@timestamp, desc)`;
      }
      
      if (huntId === 'malware-execution-hunt') {
        return `#type=edr
| in(sha256, [${allHashes.filter(h => h.length === 64).map(h => `"${h}"`).join(', ')}])
| table(host, user, process_path, sha256, @timestamp)
| sort(@timestamp, desc)`;
      }
      
      if (huntId === 'credential-abuse-hunt') {
        return `#type=idp
| in(email, [${iocs.emails?.map(e => `"${e}"`).join(', ') || ''}])
| where action = "login"
| stats count() by email, src_ip
| sort(_count, desc)`;
      }
      
      return `// Hunt template not found for: ${huntId}
// Please check the hunt ID and try again
#type=*
| where @timestamp >= now()-24h
| stats count() by sourcetype
| sort -count`;
  }
};