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

export const generateHuntIdeas = (iocs: { [key: string]: string[] }): HuntIdea[] => {
  const ideas: HuntIdea[] = [];
  
  // IP-based hunts
  if (iocs.ipv4?.length > 0 || iocs.ipv6?.length > 0) {
    ideas.push({
      id: 'ip-c2-hunt',
      title: 'C2 Infrastructure Hunt',
      description: 'Hunt for command and control communication using suspicious IP addresses',
      techniques: ['T1071.001'],
      template: 'ip-proxy-hunt',
      repo: 'proxy',
      confidence: 'high'
    });
    
    ideas.push({
      id: 'ip-lateral-hunt',
      title: 'Lateral Movement Detection',
      description: 'Detect potential lateral movement to suspicious IP addresses',
      techniques: ['T1570'],
      template: 'ip-network-hunt',
      repo: 'edr',
      confidence: 'medium'
    });
  }
  
  // Domain-based hunts
  if (iocs.domains?.length > 0) {
    ideas.push({
      id: 'domain-c2-hunt',
      title: 'Domain-based C2 Hunt',
      description: 'Hunt for suspicious domain communications across DNS and proxy logs',
      techniques: ['T1071.001', 'T1090'],
      template: 'domain-dns-hunt',
      repo: 'dns',
      confidence: 'high'
    });
  }
  
  // Hash-based hunts
  if (iocs.sha256?.length > 0 || iocs.md5?.length > 0) {
    ideas.push({
      id: 'malware-execution-hunt',
      title: 'Malware Execution Hunt',
      description: 'Hunt for known malicious file executions across endpoints',
      techniques: ['T1059.001', 'T1055'],
      template: 'hash-edr-hunt',
      repo: 'edr',
      confidence: 'high'
    });
    
    ideas.push({
      id: 'file-discovery-hunt',
      title: 'Malicious File Discovery',
      description: 'Search for presence of known malicious files in the environment',
      techniques: ['T1083'],
      template: 'hash-discovery-hunt',
      repo: 'edr',
      confidence: 'medium'
    });
  }
  
  // Email-based hunts
  if (iocs.emails?.length > 0) {
    ideas.push({
      id: 'credential-abuse-hunt',
      title: 'Compromised Account Hunt',
      description: 'Hunt for suspicious authentication activity from compromised accounts',
      techniques: ['T1078'],
      template: 'email-idp-hunt',
      repo: 'idp',
      confidence: 'high'
    });
  }
  
  return ideas;
};

export const getHuntTemplate = (huntId: string, iocs: { [key: string]: string[] }): string => {
  switch (huntId) {
    case 'ip-c2-hunt':
      return `#type=proxy
| in(dst_ip, [${iocs.ipv4?.map(ip => `"${ip}"`).join(', ') || ''}])
| stats dc(src_ip) as unique_sources by dst_ip
| where unique_sources > 1
| sort(unique_sources, desc)`;
      
    case 'domain-c2-hunt':
      return `#type=dns OR #type=proxy
| in(domain, [${iocs.domains?.map(d => `"${d}"`).join(', ') || ''}])
| timechart(span=1h, by=domain)
| sort(@timestamp, desc)`;
      
    case 'malware-execution-hunt':
      return `#type=edr
| in(sha256, [${iocs.sha256?.map(h => `"${h}"`).join(', ') || ''}])
| table(host, user, process_path, sha256, @timestamp)
| sort(@timestamp, desc)`;
      
    case 'credential-abuse-hunt':
      return `#type=idp
| in(email, [${iocs.emails?.map(e => `"${e}"`).join(', ') || ''}])
| where action = "login"
| stats count() by email, src_ip
| sort(_count, desc)`;
      
    default:
      return '// Hunt template not found';
  }
};