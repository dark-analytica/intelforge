import React, { useState, useCallback, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from '@/hooks/use-toast';
import { llmService } from '@/lib/llm-service';
import { mitreAttackService } from '@/lib/mitre-attack-service';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Brain, 
  Sparkles, 
  Clock, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  ExternalLink,
  Info,
  AlertTriangle,
  Settings
} from 'lucide-react';

interface TTP {
  technique_id: string;
  subtechnique_id?: string;
  tactic?: string;
  behavior: string;
  evidence_excerpt: string;
}

interface Detection {
  title: string;
  description: string;
  data_sources: string[];
  suggested_query_snippets: string[];
}

interface ExtractedEntities {
  products: string[];
  operating_systems: string[];
  cloud_providers: string[];
  identities: string[];
  tools: string[];
  malware: string[];
}

interface TTpExtractionResult {
  summary: string;
  ttps: TTP[];
  detections: Detection[];
  entities: ExtractedEntities;
  model_used: string;
  processing_time_ms: number;
}

interface TTpExtractorProps {
  text: string;
  onTTpApply?: (ttp: TTP, detection?: Detection) => void;
  onExtractionComplete?: (result: TTpExtractionResult) => void;
  onTTPsExtracted?: (ttps: TTP[], detections: Detection[], entities: ExtractedEntities) => void;
}

export const TTpExtractor = ({ text, onTTpApply, onExtractionComplete, onTTPsExtracted }: TTpExtractorProps) => {
  const [isExtracting, setIsExtracting] = useState(false);
  const [result, setResult] = useState<TTpExtractionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [progress, setProgress] = useState(0);
  const [selectedModel, setSelectedModel] = useState('claude-3-haiku-20240307');
  const [availableModels, setAvailableModels] = useState<Array<{value: string, label: string, provider: string}>>([]);
  const [hasApiKeys, setHasApiKeys] = useState(false);

  useEffect(() => {
    loadAvailableModels();
    // Initialize MITRE ATT&CK service
    mitreAttackService.initialize().catch(console.error);
  }, []);

  const loadAvailableModels = async () => {
    try {
      const hasKeys = await llmService.hasConfiguredProviders();
      setHasApiKeys(hasKeys);
      
      if (hasKeys) {
        const providers = await llmService.getConfiguredProviders();
        const models: Array<{value: string, label: string, provider: string}> = [];
        
        // Prioritize OpenRouter models (browser-friendly)
        if (providers.includes('OpenRouter')) {
          models.push(
            { value: 'anthropic/claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet (OpenRouter) ⭐', provider: 'OpenRouter' },
            { value: 'anthropic/claude-3-haiku', label: 'Claude 3 Haiku (OpenRouter)', provider: 'OpenRouter' },
            { value: 'openai/gpt-4o', label: 'GPT-4o (OpenRouter)', provider: 'OpenRouter' },
            { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini (OpenRouter)', provider: 'OpenRouter' }
          );
        }
        
        if (providers.includes('Anthropic')) {
          models.push(
            { value: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet (Direct)', provider: 'Anthropic' },
            { value: 'claude-3-haiku-20240307', label: 'Claude 3 Haiku (Direct)', provider: 'Anthropic' },
            { value: 'claude-3-sonnet-20240229', label: 'Claude 3 Sonnet (Direct)', provider: 'Anthropic' }
          );
        }
        
        if (providers.includes('OpenAI')) {
          models.push(
            { value: 'gpt-4o', label: 'GPT-4o (Direct)', provider: 'OpenAI' },
            { value: 'gpt-4o-mini', label: 'GPT-4o Mini (Direct)', provider: 'OpenAI' },
            { value: 'gpt-4', label: 'GPT-4 (Direct)', provider: 'OpenAI' },
            { value: 'gpt-3.5-turbo', label: 'GPT-3.5 Turbo (Direct)', provider: 'OpenAI' }
          );
        }
        
        if (providers.includes('Google Gemini')) {
          models.push(
            { value: 'gemini-pro', label: 'Gemini Pro (Direct)', provider: 'Google' },
            { value: 'gemini-1.5-pro', label: 'Gemini 1.5 Pro (Direct)', provider: 'Google' }
          );
        }
        
        setAvailableModels(models);
        
        // Set default model to first available
        if (models.length > 0) {
          setSelectedModel(models[0].value);
        }
      }
    } catch (error) {
      console.error('Failed to load available models:', error);
    }
  };

  const extractTTps = async () => {
    if (!text?.trim()) {
      toast({ title: 'No text', description: 'Please provide text to extract TTPs from', variant: 'destructive' });
      return;
    }

    if (!hasApiKeys) {
      toast({ 
        title: 'No API Keys', 
        description: 'Please configure API keys in Settings to use AI TTP extraction',
        variant: 'destructive' 
      });
      return;
    }

    setIsExtracting(true);
    setError(null);
    setProgress(10);
    const startTime = Date.now();

    try {
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 15, 85));
      }, 800);

      const response = await llmService.extractTTPs({
        systemPrompt: '', // Will be set by the service
        userPrompt: `You are a cybersecurity analyst expert in MITRE ATT&CK framework and threat detection. Analyze the following threat intelligence text and extract actionable TTPs and detection strategies.

IMPORTANT: Focus ONLY on cybersecurity threats, malware, attack techniques, and threat actor behaviors. Ignore:
- Website navigation elements, menus, footers
- Advertisement content and tracking
- General business information
- Non-threat related technical content
- Social media links and sharing buttons

Text to analyze:
${text}

Provide a structured JSON response with:

{
  "summary": "Brief summary of the main threat activity described",
  "ttps": [
    {
      "technique_id": "T1234",
      "subtechnique_id": "T1234.001",
      "tactic": "Initial Access",
      "behavior": "Specific behavior observed",
      "evidence_excerpt": "Exact quote from text supporting this TTP"
    }
  ],
  "detections": [
    {
      "title": "Detection Rule Name",
      "description": "What this detection identifies",
      "data_sources": ["Process Creation", "Network Traffic", "File Monitoring"],
      "suggested_query_snippets": [
        "process_name contains 'malicious.exe'",
        "network_destination contains 'evil.com'"
      ]
    }
  ],
  "entities": {
    "products": ["Windows", "Office 365"],
    "operating_systems": ["Windows 10", "macOS"],
    "cloud_providers": ["AWS", "Azure"],
    "identities": ["admin@company.com"],
    "tools": ["PowerShell", "Cobalt Strike"],
    "malware": ["TrickBot", "Emotet"]
  }
}

Focus on practical, actionable detections that security teams can implement.`,
        preferredModel: selectedModel,
        maxTokens: 4000,
        temperature: 0.2
      });

      clearInterval(progressInterval);
      setProgress(100);

      // Parse the AI response into structured format
      const processingTime = Date.now() - startTime;
      const parsedResult = parseAIResponse(response.content, response.model, processingTime);
      
      setResult(parsedResult);
      setIsOpen(true);
      
      // Call the extraction complete callback if provided
      if (onExtractionComplete) {
        onExtractionComplete(parsedResult);
      }
      
      // Call the TTPs extracted callback if provided
      if (onTTPsExtracted) {
        onTTPsExtracted(parsedResult.ttps, parsedResult.detections, parsedResult.entities);
      }
      
      toast({ 
        title: 'TTPs Extracted', 
        description: `Found ${parsedResult.ttps.length} TTPs and ${parsedResult.detections.length} detection ideas` 
      });
    } catch (err: any) {
      console.error('TTP extraction error:', err);
      const errorMessage = err.message || 'Failed to extract TTPs';
      setError(errorMessage);
      
      // Provide specific guidance for CORS/network errors
      if (errorMessage.includes('CORS') || errorMessage.includes('Failed to fetch')) {
        toast({ 
          title: 'CORS Error - Use OpenRouter Instead', 
          description: 'Direct API calls are blocked by browser security. Get an OpenRouter API key (openrouter.ai) - it supports Claude, GPT, and other models without CORS issues.',
          variant: 'destructive' 
        });
      } else {
        toast({ 
          title: 'Extraction Failed', 
          description: errorMessage,
          variant: 'destructive' 
        });
      }
    } finally {
      setIsExtracting(false);
      setTimeout(() => setProgress(0), 1000);
    }
  };

  const parseAIResponse = (content: string, model: string, processingTime: number): TTpExtractionResult => {
    try {
      // Try to parse as JSON first
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          summary: parsed.summary || 'AI analysis completed.',
          ttps: parsed.ttps || [],
          detections: parsed.detections || [],
          entities: parsed.entities || {
            products: [],
            operating_systems: [],
            cloud_providers: [],
            identities: [],
            tools: [],
            malware: []
          },
          model_used: model,
          processing_time_ms: processingTime
        };
      }
    } catch (error) {
      console.warn('Failed to parse JSON response, falling back to text parsing:', error);
    }

    // Fallback to text parsing
    const ttps: TTP[] = [];
    const detections: Detection[] = [];
    let summary = '';
    
    // Extract summary
    const summaryMatch = content.match(/summary[:\s]*(.*?)(?:\n\n|$)/i);
    if (summaryMatch) {
      summary = summaryMatch[1].trim();
    }
    
    // Extract TTPs with better context
    const ttpRegex = /T\d{4}(?:\.\d{3})?/g;
    const ttpMatches = [...content.matchAll(ttpRegex)];
    
    ttpMatches.forEach((match) => {
      const ttpId = match[0];
      const contextStart = Math.max(0, match.index! - 150);
      const contextEnd = Math.min(content.length, match.index! + 250);
      const context = content.substring(contextStart, contextEnd);
      
      // Clean up context and extract meaningful evidence
      const cleanContext = context
        .replace(/\s+/g, ' ')
        .replace(/[^\w\s\.\,\-\(\)]/g, '')
        .trim();
      
      // Extract behavior description from context
      const sentences = cleanContext.split(/[\.!?]+/).filter(s => s.trim().length > 10);
      const relevantSentence = sentences.find(sentence => 
        sentence.toLowerCase().includes(ttpId.toLowerCase()) ||
        sentence.toLowerCase().includes('attack') ||
        sentence.toLowerCase().includes('malicious') ||
        sentence.toLowerCase().includes('technique')
      );
      
      const techniqueInfo = getTechniqueInfo(ttpId);
      
      // Clean up behavior text - use technique description instead of raw evidence
      const behavior = techniqueInfo.description;
      
      // Create clean evidence excerpt from relevant context
      let evidenceExcerpt = '';
      if (relevantSentence) {
        // Clean up the evidence text
        evidenceExcerpt = relevantSentence
          .replace(/\s+/g, ' ')  // Normalize whitespace
          .replace(/^["\s-]+|["\s-]+$/g, '')  // Remove leading/trailing quotes and dashes
          .trim();
        
        // Truncate if too long
        if (evidenceExcerpt.length > 120) {
          evidenceExcerpt = evidenceExcerpt.substring(0, 120) + '...';
        }
      } else {
        // Fallback to clean context
        evidenceExcerpt = cleanContext
          .replace(/\s+/g, ' ')
          .substring(0, 120) + '...';
      }
      
      ttps.push({
        technique_id: ttpId,
        behavior: behavior,
        evidence_excerpt: evidenceExcerpt,
        tactic: techniqueInfo.tactic
      });
    });
    
    // Generate enhanced detection ideas based on content
    const detectionKeywords = [
      'powershell', 'cmd.exe', 'wscript', 'cscript', 'regsvr32', 'rundll32',
      'certutil', 'bitsadmin', 'mshta', 'installutil', 'regasm'
    ];
    
    const foundKeywords = detectionKeywords.filter(keyword => 
      content.toLowerCase().includes(keyword)
    );
    
    if (foundKeywords.length > 0) {
      detections.push({
        title: 'Suspicious Process Execution',
        description: 'Detect execution of potentially malicious processes',
        data_sources: ['Process Creation', 'Command Line', 'Process Network'],
        suggested_query_snippets: [
          `event_simpleName=ProcessRollup2 AND (${foundKeywords.map(k => `FileName="${k}"`).join(' OR ')})`,
          `CommandLine contains ("${foundKeywords.join('" OR "')}")`
        ]
      });
    }
    
    if (content.toLowerCase().includes('network') || content.toLowerCase().includes('c2') || content.toLowerCase().includes('command')) {
      detections.push({
        title: 'Network Communication Monitoring',
        description: 'Monitor for suspicious network connections',
        data_sources: ['Network Traffic', 'DNS', 'HTTP'],
        suggested_query_snippets: [
          'event_simpleName=DnsRequest AND DomainName contains suspicious_domain',
          'event_simpleName=NetworkConnect AND RemoteAddressIP4 != LocalAddressIP4'
        ]
      });
    }
    
    return {
      summary: summary || 'AI analysis of threat intelligence completed.',
      ttps,
      detections,
      entities: {
        products: extractProducts(content),
        operating_systems: extractOperatingSystems(content),
        cloud_providers: extractCloudProviders(content),
        identities: extractIdentities(content),
        tools: extractTools(content),
        malware: extractMalware(content)
      },
      model_used: model,
      processing_time_ms: processingTime
    };
  };

  const getTechniqueInfo = (techniqueId: string) => {
    // Use MITRE ATT&CK service for authoritative technique information
    const mitreInfo = mitreAttackService.getTechniqueInfo(techniqueId);
    
    if (mitreInfo) {
      return {
        name: mitreInfo.name,
        description: mitreInfo.description,
        tactic: mitreInfo.tactic,
        platforms: mitreInfo.platforms,
        dataSources: mitreInfo.dataSources,
        mitigations: mitreInfo.mitigations,
        detectionMethods: mitreInfo.detectionMethods
      };
    }

    // Fallback for unknown techniques
    return { 
      name: `Technique ${techniqueId}`, 
      description: 'MITRE ATT&CK technique - see attack.mitre.org for details',
      tactic: 'Unknown',
      platforms: [],
      dataSources: [],
      mitigations: [],
      detectionMethods: []
    };
  };

  const extractProducts = (content: string): string[] => {
    const productPatterns = [
      /\b(windows|office|excel|word|outlook|powerpoint|teams)\b/gi,
      /\b(adobe|acrobat|reader|flash|photoshop)\b/gi,
      /\b(chrome|firefox|safari|edge|internet explorer)\b/gi,
      /\b(vmware|virtualbox|hyper-v|citrix)\b/gi
    ];
    
    const products = new Set<string>();
    productPatterns.forEach(pattern => {
      const matches = content.match(pattern) || [];
      matches.forEach(match => products.add(match.toLowerCase()));
    });
    
    return Array.from(products);
  };

  const extractOperatingSystems = (content: string): string[] => {
    const osPatterns = [
      /\b(windows\s*(?:10|11|7|8|xp|server|2019|2022))\b/gi,
      /\b(linux|ubuntu|centos|redhat|debian|kali)\b/gi,
      /\b(macos|mac\s*os|osx)\b/gi,
      /\b(android|ios)\b/gi
    ];
    
    const oses = new Set<string>();
    osPatterns.forEach(pattern => {
      const matches = content.match(pattern) || [];
      matches.forEach(match => oses.add(match.toLowerCase()));
    });
    
    return Array.from(oses);
  };

  const extractCloudProviders = (content: string): string[] => {
    const cloudPatterns = [
      /\b(aws|amazon\s*web\s*services|ec2|s3)\b/gi,
      /\b(azure|microsoft\s*azure|office\s*365)\b/gi,
      /\b(google\s*cloud|gcp|gmail|workspace)\b/gi,
      /\b(dropbox|onedrive|sharepoint|teams)\b/gi
    ];
    
    const clouds = new Set<string>();
    cloudPatterns.forEach(pattern => {
      const matches = content.match(pattern) || [];
      matches.forEach(match => clouds.add(match.toLowerCase()));
    });
    
    return Array.from(clouds);
  };

  const extractIdentities = (content: string): string[] => {
    const identityPatterns = [
      /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
      /\b(admin|administrator|root|user|guest)\b/gi,
      /\b[A-Z][a-z]+\s+[A-Z][a-z]+\b/g // Names
    ];
    
    const identities = new Set<string>();
    identityPatterns.forEach(pattern => {
      const matches = content.match(pattern) || [];
      matches.forEach(match => identities.add(match.toLowerCase()));
    });
    
    return Array.from(identities).slice(0, 10); // Limit to avoid too many results
  };

  const extractTools = (content: string): string[] => {
    const toolPatterns = [
      /\b(powershell|cmd|bash|python|perl|ruby|java|javaw)\.exe?\b/gi,
      /\b(metasploit|cobalt strike|empire|covenant|sliver|havoc)\b/gi,
      /\b(mimikatz|bloodhound|sharphound|rubeus|kerberoast)\b/gi,
      /\b(psexec|wmic|schtasks|at\.exe|sc\.exe)\b/gi
    ];
    
    const tools = new Set<string>();
    toolPatterns.forEach(pattern => {
      const matches = content.match(pattern) || [];
      matches.forEach(match => tools.add(match.toLowerCase()));
    });
    
    return Array.from(tools);
  };

  const extractMalware = (content: string): string[] => {
    const malwarePatterns = [
      /\b(emotet|trickbot|qakbot|icedid|dridex|zeus|banking trojan)\b/gi,
      /\b(ransomware|ryuk|conti|lockbit|revil|sodinokibi)\b/gi,
      /\b(apt\d+|lazarus|fancy bear|cozy bear|carbanak)\b/gi,
      /\b(backdoor|trojan|rootkit|keylogger|stealer)\b/gi
    ];
    
    const malware = new Set<string>();
    malwarePatterns.forEach(pattern => {
      const matches = content.match(pattern) || [];
      matches.forEach(match => malware.add(match.toLowerCase()));
    });
    
    return Array.from(malware);
  };

  const copyTTP = async (ttp: TTP) => {
    const text = `${ttp.technique_id}: ${ttp.behavior}\nTactic: ${ttp.tactic}\nEvidence: ${ttp.evidence_excerpt}`;
    await navigator.clipboard.writeText(text);
    toast({ title: 'Copied', description: 'TTP details copied to clipboard' });
  };

  const getAttackUrl = (techniqueId: string) => {
    return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
  };

  const getTacticColor = (tactic?: string) => {
    const colors: Record<string, string> = {
      'Reconnaissance': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      'Resource Development': 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
      'Initial Access': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      'Execution': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
      'Persistence': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      'Privilege Escalation': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      'Defense Evasion': 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
      'Credential Access': 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900 dark:text-cyan-200',
      'Discovery': 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200',
      'Lateral Movement': 'bg-violet-100 text-violet-800 dark:bg-violet-900 dark:text-violet-200',
      'Collection': 'bg-pink-100 text-pink-800 dark:bg-pink-900 dark:text-pink-200',
      'Command and Control': 'bg-rose-100 text-rose-800 dark:bg-rose-900 dark:text-rose-200',
      'Exfiltration': 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200',
      'Impact': 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200'
    };
    return colors[tactic || ''] || 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200';
  };

  if (!text?.trim()) {
    return (
      <Card className="border-dashed">
        <CardContent className="pt-6">
          <div className="text-center text-muted-foreground">
            <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Extract CTI text first to analyze TTPs with AI</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="font-terminal text-glow flex items-center gap-2">
              <Sparkles className="h-5 w-5" />
              AI TTP Extractor
            </CardTitle>
            <CardDescription>
              Extract TTPs, tactics, and detection ideas using AI analysis
            </CardDescription>
          </div>
          <Button 
            onClick={extractTTps}
            disabled={isExtracting || !hasApiKeys}
            className="gap-2"
          >
            <Brain className="h-4 w-4" />
            {isExtracting ? 'Analyzing...' : 'Extract TTPs'}
          </Button>
        </div>
        
        <div className="space-y-3 mb-4">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4" />
            <span className="text-sm font-medium">AI Model:</span>
          </div>
          {hasApiKeys ? (
            <Select value={selectedModel} onValueChange={setSelectedModel}>
              <SelectTrigger className="w-full max-w-md">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {availableModels.map((model) => (
                  <SelectItem key={model.value} value={model.value}>
                    <div className="flex items-center justify-between w-full">
                      <span className="truncate">{model.label}</span>
                      <Badge variant="outline" className="text-xs ml-2 shrink-0">
                        {model.provider}
                      </Badge>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <div className="space-y-2 p-3 bg-muted/30 rounded-md">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">No API keys configured</span>
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => {
                    toast({ 
                      title: 'Configure API Keys', 
                      description: 'Please go to Settings to configure your AI provider API keys' 
                    });
                  }}
                >
                  Configure
                </Button>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                💡 Tip: Use OpenRouter API key for best browser compatibility - it supports Claude, GPT, and other models without CORS issues.
              </p>
            </div>
          )}
        </div>
        
        {isExtracting && (
          <div className="space-y-2">
            <Progress value={progress} className="w-full" />
            <p className="text-sm text-muted-foreground">
              Analyzing text with AI... ({Math.round(progress)}%)
            </p>
          </div>
        )}
      </CardHeader>

      {error && (
        <CardContent>
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        </CardContent>
      )}

      {result && (
        <Collapsible open={isOpen} onOpenChange={setIsOpen}>
          <CollapsibleTrigger asChild>
            <CardContent className="cursor-pointer hover:bg-muted/50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <Badge variant="secondary" className="gap-1">
                    <Clock className="h-3 w-3" />
                    {result.processing_time_ms}ms
                  </Badge>
                  <Badge variant="outline">{result.model_used}</Badge>
                  <span className="text-sm text-muted-foreground">
                    {result.ttps.length} TTPs • {result.detections.length} Detections
                  </span>
                </div>
                {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
            </CardContent>
          </CollapsibleTrigger>

          <CollapsibleContent>
            <CardContent className="pt-0">
              <Tabs defaultValue="summary" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="summary">Summary</TabsTrigger>
                  <TabsTrigger value="ttps">TTPs ({result.ttps.length})</TabsTrigger>
                  <TabsTrigger value="detections">Detections ({result.detections.length})</TabsTrigger>
                  <TabsTrigger value="entities">Entities</TabsTrigger>
                </TabsList>

                <TabsContent value="summary" className="mt-4">
                  <div className="prose prose-sm max-w-none">
                    <p className="text-foreground">{result.summary}</p>
                  </div>
                </TabsContent>

                <TabsContent value="ttps" className="mt-4">
                  <div className="space-y-4">
                    {result.ttps.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        <Info className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        No TTPs identified in this text
                      </div>
                    ) : (
                      result.ttps.map((ttp, index) => (
                        <Card key={index} className="bg-muted/30">
                          <CardContent className="pt-4">
                            <div className="space-y-3">
                              <div className="flex items-start justify-between gap-4">
                                <div className="flex-1 space-y-2">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <Badge variant="outline" className="font-mono">
                                      {ttp.technique_id}
                                      {ttp.subtechnique_id && `.${ttp.subtechnique_id.split('.')[1]}`}
                                    </Badge>
                                    {ttp.tactic && (
                                      <Badge className={getTacticColor(ttp.tactic)}>
                                        {ttp.tactic}
                                      </Badge>
                                    )}
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      asChild
                                      className="h-6 px-2"
                                    >
                                      <a 
                                        href={getAttackUrl(ttp.technique_id)} 
                                        target="_blank" 
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-1"
                                      >
                                        <ExternalLink className="h-3 w-3" />
                                        MITRE
                                      </a>
                                    </Button>
                                  </div>
                                  
                                  <div className="space-y-1">
                                    <h4 className="font-medium text-sm">
                                      {getTechniqueInfo(ttp.technique_id).name}
                                    </h4>
                                    <p className="text-xs text-muted-foreground leading-relaxed">
                                      {getTechniqueInfo(ttp.technique_id).description}
                                    </p>
                                  </div>
                                  
                                  <blockquote className="border-l-2 pl-4 italic text-sm text-muted-foreground max-w-none">
                                    <div className="line-clamp-3 break-words">
                                      "{ttp.evidence_excerpt.length > 200 ? ttp.evidence_excerpt.substring(0, 200) + '...' : ttp.evidence_excerpt}"
                                    </div>
                                  </blockquote>
                                </div>
                                
                                <div className="flex gap-1">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyTTP(ttp)}
                                    className="h-8 w-8 p-0"
                                  >
                                    <Copy className="h-3 w-3" />
                                  </Button>
                                  {onTTpApply && (
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() => onTTpApply(ttp)}
                                      className="gap-1"
                                    >
                                      <Sparkles className="h-3 w-3" />
                                      Apply
                                    </Button>
                                  )}
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="detections" className="mt-4">
                  <div className="space-y-4">
                    {result.detections.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        <Info className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        No detection ideas generated
                      </div>
                    ) : (
                      result.detections.map((detection, index) => (
                        <Card key={index} className="bg-muted/30">
                          <CardContent className="pt-4">
                            <div className="space-y-3">
                              <div className="flex items-start justify-between gap-4">
                                <div className="flex-1 space-y-2">
                                  <h4 className="font-medium">{detection.title}</h4>
                                  <p className="text-sm text-muted-foreground">{detection.description}</p>
                                  
                                  <div className="flex flex-wrap gap-1">
                                    {detection.data_sources.map((source, i) => (
                                      <Badge key={i} variant="secondary" className="text-xs">
                                        {source}
                                      </Badge>
                                    ))}
                                  </div>
                                  
                                  {detection.suggested_query_snippets.length > 0 && (
                                    <div className="space-y-1">
                                      <p className="text-xs font-medium text-muted-foreground">Query Ideas:</p>
                                      {detection.suggested_query_snippets.map((snippet, i) => (
                                        <code key={i} className="block text-xs bg-background p-2 rounded border">
                                          {snippet}
                                        </code>
                                      ))}
                                    </div>
                                  )}
                                </div>
                                
                                {onTTpApply && (
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => onTTpApply({} as TTP, detection)}
                                    className="gap-1"
                                  >
                                    <Sparkles className="h-3 w-3" />
                                    Apply
                                  </Button>
                                )}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="entities" className="mt-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries(result.entities).map(([category, items]) => (
                      <div key={category}>
                        <h4 className="font-medium mb-2 capitalize">
                          {category.replace('_', ' ')} ({items.length})
                        </h4>
                        {items.length === 0 ? (
                          <p className="text-sm text-muted-foreground">None identified</p>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {items.map((item, i) => (
                              <Badge key={i} variant="outline" className="text-xs">
                                {item}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </CollapsibleContent>
        </Collapsible>
      )}
    </Card>
  );
};