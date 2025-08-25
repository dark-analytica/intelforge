import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Target, Copy, CheckCircle, ExternalLink } from 'lucide-react';
import { IOCSet } from '@/lib/ioc-extractor';
import { generateHuntIdeas, getHuntTemplate, attackTechniques, type HuntIdea } from '@/lib/attack-hunts';
import { useToast } from '@/hooks/use-toast';

interface HuntSuggestionsProps {
  iocs: IOCSet;
  onApplyHunt: (template: string, huntId: string) => void;
}

export const HuntSuggestions = ({ iocs, onApplyHunt }: HuntSuggestionsProps) => {
  const [copiedHunt, setCopiedHunt] = useState<string | null>(null);
  const { toast } = useToast();
  
  const huntIdeas = generateHuntIdeas(iocs as unknown as { [key: string]: string[] });
  const totalIOCs = Object.values(iocs).flat().length;

  const handleCopyHunt = async (huntId: string, template: string) => {
    try {
      await navigator.clipboard.writeText(template);
      setCopiedHunt(huntId);
      setTimeout(() => setCopiedHunt(null), 2000);
      toast({
        title: "Hunt copied",
        description: "Hunt template copied to clipboard"
      });
    } catch (error) {
      toast({
        title: "Copy failed",
        description: "Failed to copy hunt template",
        variant: "destructive"
      });
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high': return 'bg-green-500/10 text-green-400 border-green-500/20';
      case 'medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      case 'low': return 'bg-red-500/10 text-red-400 border-red-500/20';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  if (totalIOCs === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="font-terminal text-glow flex items-center gap-2">
            <Shield className="h-5 w-5" />
            ATT&CK Hunt Ideas
          </CardTitle>
          <CardDescription>
            AI-generated hunt suggestions mapped to MITRE ATT&CK techniques
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Alert>
            <Target className="h-4 w-4" />
            <AlertDescription>
              Extract IOCs first to generate relevant hunt suggestions mapped to MITRE ATT&CK techniques.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="font-terminal text-glow flex items-center gap-2">
            <Shield className="h-5 w-5" />
            ATT&CK Hunt Ideas
          </CardTitle>
          <CardDescription>
            Hunt suggestions based on your extracted IOCs, mapped to MITRE ATT&CK techniques
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4 mb-4">
            <Badge variant="outline">{huntIdeas.length} Hunt Ideas</Badge>
            <Badge variant="outline">{totalIOCs} IOCs Available</Badge>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4">
        {huntIdeas.map((hunt) => {
          const template = getHuntTemplate(hunt.id, iocs as unknown as { [key: string]: string[] });
          
          return (
            <Card key={hunt.id} className="transition-all hover:shadow-md">
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <CardTitle className="text-base font-semibold flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      {hunt.title}
                    </CardTitle>
                    <CardDescription className="mt-1">
                      {hunt.description}
                    </CardDescription>
                  </div>
                  <Badge 
                    variant="outline" 
                    className={getConfidenceColor(hunt.confidence)}
                  >
                    {hunt.confidence}
                  </Badge>
                </div>
              </CardHeader>
              
              <CardContent className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium mb-2">MITRE ATT&CK Techniques</h4>
                  <div className="flex flex-wrap gap-2">
                    {hunt.techniques.map((techniqueId) => {
                      const technique = attackTechniques[techniqueId];
                      return (
                        <Badge 
                          key={techniqueId} 
                          variant="secondary" 
                          className="gap-1 cursor-pointer hover:bg-secondary/80"
                          onClick={() => window.open(`https://attack.mitre.org/techniques/${techniqueId}`, '_blank')}
                        >
                          {techniqueId}
                          <ExternalLink className="h-3 w-3" />
                        </Badge>
                      );
                    })}
                  </div>
                  
                  {hunt.techniques.length > 0 && (
                    <div className="mt-2 text-xs text-muted-foreground">
                      Tactic: {attackTechniques[hunt.techniques[0]]?.tactic}
                    </div>
                  )}
                </div>

                <div>
                  <h4 className="text-sm font-medium mb-2">Hunt Template Preview</h4>
                  <div className="bg-muted/50 border rounded-lg p-3">
                    <pre className="text-xs font-mono overflow-auto whitespace-pre-wrap">
                      {template}
                    </pre>
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopyHunt(hunt.id, template)}
                    className="gap-2"
                  >
                    {copiedHunt === hunt.id ? (
                      <>
                        <CheckCircle className="h-4 w-4" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4" />
                        Copy Hunt
                      </>
                    )}
                  </Button>
                  
                  <Button
                    size="sm"
                    onClick={() => onApplyHunt(template, hunt.id)}
                    className="gap-2"
                  >
                    <Target className="h-4 w-4" />
                    Apply to Queries
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {huntIdeas.length === 0 && (
        <Alert>
          <Shield className="h-4 w-4" />
          <AlertDescription>
            No hunt suggestions available for the current IOC types. Try extracting more diverse IOCs (IPs, domains, hashes, emails).
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};