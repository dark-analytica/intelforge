import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ChevronDown, ChevronUp, Brain, Copy, ExternalLink, Sparkles, Clock, Info } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

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
}

export const TTpExtractor = ({ text, onTTpApply, onExtractionComplete }: TTpExtractorProps) => {
  const [isExtracting, setIsExtracting] = useState(false);
  const [result, setResult] = useState<TTpExtractionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [progress, setProgress] = useState(0);
  const [selectedModel, setSelectedModel] = useState('gpt-5-2025-08-07');
  const { toast } = useToast();

  const extractTTps = async () => {
    if (!text?.trim()) {
      toast({ title: 'No text', description: 'Please provide text to extract TTPs from', variant: 'destructive' });
      return;
    }

    setIsExtracting(true);
    setError(null);
    setProgress(10);

    try {
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 10, 90));
      }, 500);

      const { data, error: functionError } = await supabase.functions.invoke('extract-ttps', {
        body: { 
          text,
          model: selectedModel
        }
      });

      clearInterval(progressInterval);
      setProgress(100);

      if (functionError) {
        throw new Error(functionError.message || 'Function invocation failed');
      }

      if (data.error) {
        throw new Error(data.error);
      }

      setResult(data);
      setIsOpen(true);
      
      // Call the extraction complete callback if provided
      if (onExtractionComplete) {
        onExtractionComplete(data);
      }
      
      toast({ 
        title: 'TTPs Extracted', 
        description: `Found ${data.ttps.length} TTPs and ${data.detections.length} detection ideas` 
      });
    } catch (err: any) {
      console.error('TTP extraction error:', err);
      setError(err.message || 'Failed to extract TTPs');
      toast({ 
        title: 'Extraction Failed', 
        description: err.message || 'Failed to extract TTPs from text',
        variant: 'destructive' 
      });
    } finally {
      setIsExtracting(false);
      setTimeout(() => setProgress(0), 1000);
    }
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
              <Brain className="h-5 w-5" />
              AI TTP Extraction
            </CardTitle>
            <CardDescription>
              Extract TTPs, tactics, and detection ideas using AI analysis
            </CardDescription>
          </div>
          
          <div className="flex items-center gap-3">
            <Select value={selectedModel} onValueChange={setSelectedModel}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="gpt-5-2025-08-07">GPT-5 (30K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-5-mini-2025-08-07">GPT-5 Mini (200K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-5-nano-2025-08-07">GPT-5 Nano (200K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-4.1-2025-04-14">GPT-4.1 (30K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-4.1-mini-2025-04-14">GPT-4.1 Mini (200K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-4.1-nano-2025-04-14">GPT-4.1 Nano (200K TPM, 500 RPM)</SelectItem>
                <SelectItem value="o3-2025-04-16">O3 Reasoning (30K TPM, 500 RPM)</SelectItem>
                <SelectItem value="o4-mini-2025-04-16">O4 Mini (200K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-4o">GPT-4o Legacy (30K TPM, 500 RPM)</SelectItem>
                <SelectItem value="gpt-4o-mini">GPT-4o Mini Legacy (Fast)</SelectItem>
                <SelectItem value="gpt-4o-realtime-preview">GPT-4o Realtime (40K TPM, 200 RPM)</SelectItem>
              </SelectContent>
            </Select>
            <Button 
              onClick={extractTTps}
              disabled={isExtracting}
              className="gap-2"
            >
              <Sparkles className="h-4 w-4" />
              {isExtracting ? 'Analyzing...' : 'Extract TTPs'}
            </Button>
          </div>
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
                                  
                                  <h4 className="font-medium">{ttp.behavior}</h4>
                                  
                                  <blockquote className="border-l-2 pl-4 italic text-sm text-muted-foreground">
                                    "{ttp.evidence_excerpt}"
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