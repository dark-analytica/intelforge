// Enhanced MITRE ATT&CK technique database for IntelForge
// This provides comprehensive technique information without external dependencies

export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactic: string;
  platforms: string[];
  dataSources: string[];
  mitigations: string[];
  detectionMethods: string[];
}

class MitreAttackService {
  private techniques: Record<string, MitreTechnique> = {
    'T1003': {
      id: 'T1003',
      name: 'OS Credential Dumping',
      description: 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
      tactic: 'Credential Access',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Process Access', 'Command Line'],
      mitigations: ['Privileged Account Management', 'User Account Management'],
      detectionMethods: ['Monitor for LSASS process access', 'Detect credential dumping tools']
    },
    'T1012': {
      id: 'T1012',
      name: 'Query Registry',
      description: 'Adversaries may interact with the Windows Registry to gather information about the system.',
      tactic: 'Discovery',
      platforms: ['Windows'],
      dataSources: ['Process Creation', 'Command Line', 'Windows Registry'],
      mitigations: ['User Account Control'],
      detectionMethods: ['Monitor registry queries', 'Analyze reg.exe usage']
    },
    'T1027': {
      id: 'T1027',
      name: 'Obfuscated Files or Information',
      description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze.',
      tactic: 'Defense Evasion',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['File Creation', 'Process Creation', 'Script Execution'],
      mitigations: ['Antivirus/Antimalware', 'Execution Prevention'],
      detectionMethods: ['Analyze file entropy', 'Detect packing/encoding']
    },
    'T1036': {
      id: 'T1036',
      name: 'Masquerading',
      description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.',
      tactic: 'Defense Evasion',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['File Creation', 'Process Creation', 'Binary File Metadata'],
      mitigations: ['Execution Prevention', 'Restrict File and Directory Permissions'],
      detectionMethods: ['Monitor for suspicious file names', 'Verify digital signatures']
    },
    'T1055': {
      id: 'T1055',
      name: 'Process Injection',
      description: 'Adversaries may inject code into processes to evade process-based defenses or elevate privileges.',
      tactic: 'Defense Evasion',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Process Access', 'Process Modification'],
      mitigations: ['Behavior Prevention on Endpoint', 'Privileged Account Management'],
      detectionMethods: ['Monitor process hollowing', 'Detect DLL injection']
    },
    'T1059': {
      id: 'T1059',
      name: 'Command and Scripting Interpreter',
      description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
      tactic: 'Execution',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Command Line', 'Script Execution'],
      mitigations: ['Execution Prevention', 'Restrict Web-Based Content'],
      detectionMethods: ['Monitor command line execution', 'Analyze script content']
    },
    'T1070': {
      id: 'T1070',
      name: 'Indicator Removal',
      description: 'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence.',
      tactic: 'Defense Evasion',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['File Deletion', 'Process Creation', 'Command Line'],
      mitigations: ['Restrict File and Directory Permissions', 'Remote Data Storage'],
      detectionMethods: ['Monitor file deletion patterns', 'Track log clearing activities']
    },
    'T1082': {
      id: 'T1082',
      name: 'System Information Discovery',
      description: 'An adversary may attempt to get detailed information about the operating system and hardware.',
      tactic: 'Discovery',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Command Line', 'OS API Execution'],
      mitigations: [],
      detectionMethods: ['Monitor system information queries', 'Detect reconnaissance commands']
    },
    'T1083': {
      id: 'T1083',
      name: 'File and Directory Discovery',
      description: 'Adversaries may enumerate files and directories or search in specific locations of a host or network share.',
      tactic: 'Discovery',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Command Line', 'File Access'],
      mitigations: [],
      detectionMethods: ['Monitor file system enumeration', 'Track directory traversal']
    },
    'T1087': {
      id: 'T1087',
      name: 'Account Discovery',
      description: 'Adversaries may attempt to get a listing of valid accounts on a system or within an environment.',
      tactic: 'Discovery',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Command Line', 'OS API Execution'],
      mitigations: [],
      detectionMethods: ['Monitor account enumeration', 'Detect user listing commands']
    },
    'T1090': {
      id: 'T1090',
      name: 'Proxy',
      description: 'Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary.',
      tactic: 'Command and Control',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Network Traffic', 'Network Connection Creation', 'Process Creation'],
      mitigations: ['Network Intrusion Prevention', 'Network Segmentation'],
      detectionMethods: ['Monitor proxy usage', 'Analyze network connections']
    },
    'T1105': {
      id: 'T1105',
      name: 'Ingress Tool Transfer',
      description: 'Adversaries may transfer tools or other files from an external system into a compromised environment.',
      tactic: 'Command and Control',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Network Traffic', 'File Creation', 'Process Creation'],
      mitigations: ['Network Intrusion Prevention', 'Execution Prevention'],
      detectionMethods: ['Monitor file downloads', 'Detect tool transfers']
    },
    'T1112': {
      id: 'T1112',
      name: 'Modify Registry',
      description: 'Adversaries may interact with the Windows Registry to hide configuration information.',
      tactic: 'Defense Evasion',
      platforms: ['Windows'],
      dataSources: ['Windows Registry', 'Process Creation', 'Command Line'],
      mitigations: ['User Account Control', 'Restrict Registry Permissions'],
      detectionMethods: ['Monitor registry modifications', 'Track reg.exe usage']
    },
    'T1140': {
      id: 'T1140',
      name: 'Deobfuscate/Decode Files or Information',
      description: 'Adversaries may use obfuscated files or information to hide artifacts of an intrusion from analysis.',
      tactic: 'Defense Evasion',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'File Creation', 'Script Execution'],
      mitigations: ['Antivirus/Antimalware', 'Execution Prevention'],
      detectionMethods: ['Monitor decoding activities', 'Analyze file transformations']
    },
    'T1190': {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      description: 'Adversaries may attempt to exploit a weakness in an Internet-facing computer or program.',
      tactic: 'Initial Access',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Application Log', 'Network Traffic', 'Process Creation'],
      mitigations: ['Application Isolation and Sandboxing', 'Update Software'],
      detectionMethods: ['Monitor for exploitation attempts', 'Analyze application logs']
    },
    'T1204': {
      id: 'T1204',
      name: 'User Execution',
      description: 'An adversary may rely upon specific actions by a user in order to gain execution.',
      tactic: 'Execution',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'File Creation', 'Command Line'],
      mitigations: ['User Training', 'Execution Prevention'],
      detectionMethods: ['Monitor user-initiated execution', 'Analyze file associations']
    },
    'T1547': {
      id: 'T1547',
      name: 'Boot or Logon Autostart Execution',
      description: 'Adversaries may configure system settings to automatically execute a program during system boot.',
      tactic: 'Persistence',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'Windows Registry', 'File Creation'],
      mitigations: ['User Account Control', 'Restrict Registry Permissions'],
      detectionMethods: ['Monitor autostart locations', 'Track persistence mechanisms']
    },
    'T1566': {
      id: 'T1566',
      name: 'Phishing',
      description: 'Adversaries may send phishing messages to gain access to victim systems.',
      tactic: 'Initial Access',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Application Log', 'Network Traffic', 'File Creation'],
      mitigations: ['User Training', 'Antivirus/Antimalware'],
      detectionMethods: ['Monitor email attachments', 'Analyze web traffic']
    },
    'T1071': {
      id: 'T1071',
      name: 'Application Layer Protocol',
      description: 'Adversaries may communicate using application layer protocols to avoid detection.',
      tactic: 'Command and Control',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Network Traffic', 'Process Creation'],
      mitigations: ['Network Intrusion Prevention', 'Network Segmentation'],
      detectionMethods: ['Monitor web traffic patterns', 'Analyze HTTP/HTTPS communications']
    },
    'T1568': {
      id: 'T1568',
      name: 'Dynamic Resolution',
      description: 'Adversaries may dynamically establish connections to command and control infrastructure.',
      tactic: 'Command and Control',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Network Traffic', 'DNS'],
      mitigations: ['Network Intrusion Prevention'],
      detectionMethods: ['Monitor DNS queries', 'Detect domain generation algorithms']
    },
    'T1573': {
      id: 'T1573',
      name: 'Encrypted Channel',
      description: 'Adversaries may employ encrypted channels to communicate with command and control servers.',
      tactic: 'Command and Control',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Network Traffic'],
      mitigations: ['Network Intrusion Prevention', 'SSL/TLS Inspection'],
      detectionMethods: ['Monitor encrypted traffic patterns', 'Analyze certificate anomalies']
    },
    'T1056': {
      id: 'T1056',
      name: 'Input Capture',
      description: 'Adversaries may use methods of capturing user input to obtain credentials or collect information.',
      tactic: 'Collection',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['Process Creation', 'API Monitoring'],
      mitigations: ['User Training', 'Privileged Account Management'],
      detectionMethods: ['Monitor keylogger processes', 'Detect input capture APIs']
    },
    'T1119': {
      id: 'T1119',
      name: 'Automated Collection',
      description: 'Adversaries may use automated techniques to collect internal data.',
      tactic: 'Collection',
      platforms: ['Windows', 'Linux', 'macOS'],
      dataSources: ['File Access', 'Process Creation'],
      mitigations: ['Data Loss Prevention'],
      detectionMethods: ['Monitor bulk file access', 'Detect automated data collection']
    },
    'T1583': {
      id: 'T1583',
      name: 'Acquire Infrastructure',
      description: 'Adversaries may buy, lease, or rent infrastructure that can be used during targeting.',
      tactic: 'Resource Development',
      platforms: ['PRE'],
      dataSources: ['Internet Scan', 'Domain Registration'],
      mitigations: ['Pre-compromise'],
      detectionMethods: ['Monitor domain registrations', 'Track infrastructure acquisition']
    },
    'T1584': {
      id: 'T1584',
      name: 'Compromise Infrastructure',
      description: 'Adversaries may compromise third-party infrastructure that can be used during targeting.',
      tactic: 'Resource Development',
      platforms: ['PRE'],
      dataSources: ['Internet Scan'],
      mitigations: ['Pre-compromise'],
      detectionMethods: ['Monitor compromised infrastructure', 'Track malicious hosting']
    }
  };

  async initialize(): Promise<void> {
    // No async initialization needed for static data
    return Promise.resolve();
  }

  getTechniqueInfo(techniqueId: string): MitreTechnique | null {
    const baseId = techniqueId.split('.')[0];
    return this.techniques[baseId] || null;
  }

  searchTechniques(query: string): MitreTechnique[] {
    const searchTerm = query.toLowerCase();
    const results: MitreTechnique[] = [];

    Object.entries(this.techniques).forEach(([id, technique]) => {
      if (
        technique.name.toLowerCase().includes(searchTerm) ||
        technique.description.toLowerCase().includes(searchTerm) ||
        id.toLowerCase().includes(searchTerm) ||
        technique.tactic.toLowerCase().includes(searchTerm)
      ) {
        results.push(technique);
      }
    });

    return results.slice(0, 10);
  }

  listTechniques(): MitreTechnique[] {
    return Object.values(this.techniques);
  }
}

export const mitreAttackService = new MitreAttackService();
