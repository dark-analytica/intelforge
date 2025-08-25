import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { generateHuntIdeas, getHuntTemplate } from '@/lib/attack-hunts';
import { type IOCSet } from '@/lib/ioc-extractor';
import { Copy, ExternalLink, Sparkles, Target, Shield, Info } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface HuntSuggestionsProps {
  iocs: IOCSet;
  ttps?: any[];
  onApplyHunt?: (template: string, huntId: string) => void;
}

export const HuntSuggestions = ({ iocs, ttps = [], onApplyHunt }: HuntSuggestionsProps) => {
  const [copiedHunt, setCopiedHunt] = useState<string | null>(null);
  const { toast } = useToast();

  const handleCopyHunt = async (huntId: string, template: string) => {
    await navigator.clipboard.writeText(template);
    setCopiedHunt(huntId);
    setTimeout(() => setCopiedHunt(null), 2000);
    toast({
      title: "Hunt copied to clipboard",
      description: "The hunt template has been copied to your clipboard"
    });
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence.toLowerCase()) {
      case 'high': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200';
    }
  };

  // Convert IOCSet to the format expected by generateHuntIdeas
  const iocData = {
    ips: [...iocs.ipv4, ...iocs.ipv6],
    domains: iocs.domains,
    hashes: [...iocs.sha256, ...iocs.md5],
    emails: iocs.emails,
    urls: iocs.urls
  };

  const totalIOCs = Object.values(iocs).reduce((sum, arr) => sum + arr.length, 0);
  
  if (totalIOCs === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="pt-6">
          <div className="text-center text-muted-foreground">
            <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <h3 className="font-medium mb-2">No IOCs Available</h3>
            <p className="text-sm">Extract IOCs first to generate AI-powered hunt suggestions</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const huntIdeas = generateHuntIdeas(iocData, ttps);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="font-terminal text-glow flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Hunt Suggestions
          </CardTitle>
          <CardDescription>
            AI-powered hunt ideas based on extracted IOCs ({totalIOCs}) and TTPs ({ttps.length}) using the Pyramid of Pain framework
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>{huntIdeas.length} hunt ideas</strong> generated from {totalIOCs} IOCs and {ttps.length} TTPs. 
              Prioritizing TTP-based hunts (highest on Pyramid of Pain) for maximum adversary disruption.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {huntIdeas.length === 0 ? (
        <Card>
          <CardContent className="pt-6">
            <div className="text-center text-muted-foreground">
              <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <h3 className="font-medium mb-2">No Hunt Suggestions Available</h3>
              <p className="text-sm">
                Extract more IOCs or try different IOC types to generate hunt suggestions
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6">
          {huntIdeas.map((hunt, index) => {
            const template = getHuntTemplate(hunt.id, iocData);
            
            return (
              <Card key={hunt.id} className="bg-muted/30">
                <CardHeader>
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <CardTitle className="text-lg">{hunt.title}</CardTitle>
                        <Badge className={getConfidenceColor(hunt.confidence)}>
                          {hunt.confidence} confidence
                        </Badge>
                      </div>
                      <CardDescription className="text-sm">
                        {hunt.description}
                      </CardDescription>
                    </div>
                  </div>
                </CardHeader>
                
                <CardContent className="space-y-4">
                  {/* MITRE ATT&CK Techniques */}
                  <div>
                    <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      MITRE ATT&CK Techniques
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {hunt.techniques.map((techniqueId) => (
                        <Button
                          key={techniqueId} 
                          variant="outline" 
                          size="sm"
                          className="text-xs h-6 px-2"
                          asChild
                        >
                          <a 
                            href={`https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`}
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="flex items-center gap-1"
                          >
                            {techniqueId}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </Button>
                      ))}
                    </div>
                  </div>

                  <Separator />

                  {/* Hunt Template Preview */}
                  <div>
                    <h4 className="text-sm font-medium mb-2">Hunt Template Preview</h4>
                    <div className="bg-background rounded-md p-3 font-mono text-sm border">
                      <pre className="whitespace-pre-wrap text-xs">{template}</pre>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2 pt-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleCopyHunt(hunt.id, template)}
                      className="gap-2"
                    >
                      <Copy className="h-4 w-4" />
                      {copiedHunt === hunt.id ? 'Copied!' : 'Copy Hunt'}
                    </Button>
                    
                    {onApplyHunt && (
                      <Button
                        size="sm"
                        onClick={() => onApplyHunt(template, hunt.id)}
                        className="gap-2"
                      >
                        <Sparkles className="h-4 w-4" />
                        Apply to Queries
                      </Button>
                    )}
                    
                    <Button
                      variant="outline"
                      size="sm"
                      asChild
                      className="gap-2"
                    >
                      <a 
                        href={`https://attack.mitre.org/tactics/`}
                        target="_blank" 
                        rel="noopener noreferrer"
                      >
                        <ExternalLink className="h-4 w-4" />
                        View MITRE ATT&CK
                      </a>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
};