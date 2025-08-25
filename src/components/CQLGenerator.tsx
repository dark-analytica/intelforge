import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cqlTemplates, renderTemplate, validateCQLSyntax, defaultProfile } from '@/lib/cql-templates';
import { type IOCSet } from '@/lib/ioc-extractor';
import { Copy, Download, ExternalLink, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import Editor from '@monaco-editor/react';

interface CQLGeneratorProps {
  iocs: IOCSet;
}

export const CQLGenerator = ({ iocs }: CQLGeneratorProps) => {
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const [generatedQueries, setGeneratedQueries] = useState<Array<{ template: string; cql: string; validation: any }>>([]);
  const { toast } = useToast();

  const generateQueries = () => {
    if (!selectedTemplateId) return;

    const template = cqlTemplates.find(t => t.id === selectedTemplateId);
    if (!template) return;

    const cql = renderTemplate(template, iocs, defaultProfile);
    const validation = validateCQLSyntax(cql);

    const newQuery = {
      template: template.name,
      cql,
      validation
    };

    setGeneratedQueries(prev => [newQuery, ...prev.slice(0, 4)]); // Keep last 5 queries
  };

  const copyToClipboard = (cql: string) => {
    navigator.clipboard.writeText(cql);
    toast({
      title: "Copied to clipboard",
      description: "CQL query copied successfully"
    });
  };

  const downloadQuery = (cql: string, templateName: string) => {
    const blob = new Blob([cql], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${templateName.toLowerCase().replace(/\s+/g, '-')}.cql`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getValidationIcon = (validation: any) => {
    if (validation.valid) {
      return <CheckCircle className="h-4 w-4 text-primary" />;
    } else if (validation.errors.length > 0) {
      return <XCircle className="h-4 w-4 text-destructive" />;
    }
    return <AlertTriangle className="h-4 w-4 text-warning" />;
  };

  const getValidationStatus = (validation: any) => {
    if (validation.valid) return 'PARSES ✓';
    if (validation.errors.length > 0) return 'INVALID ✖';
    return 'CHECK FIELDS ⚠';
  };

  const getValidationClass = (validation: any) => {
    if (validation.valid) return 'status-valid';
    if (validation.errors.length > 0) return 'status-error';
    return 'status-warning';
  };

  // Filter templates based on available IOCs
  const availableTemplates = cqlTemplates.filter(template => {
    return template.requiredIOCTypes.some(type => {
      const iocArray = iocs[type];
      return iocArray && iocArray.length > 0;
    });
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="font-terminal text-glow">CQL Query Generator</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4">
            <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Select a CQL template..." />
              </SelectTrigger>
              <SelectContent>
                {availableTemplates.map(template => (
                  <SelectItem key={template.id} value={template.id}>
                    <div className="flex flex-col">
                      <span>{template.name}</span>
                      <span className="text-xs text-muted-foreground">{template.description}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            
            <Button 
              onClick={generateQueries}
              disabled={!selectedTemplateId}
              className="gap-2"
            >
              Generate CQL
            </Button>
          </div>

          {selectedTemplateId && (
            <div className="flex flex-wrap gap-2">
              {cqlTemplates.find(t => t.id === selectedTemplateId)?.requiredIOCTypes.map(type => (
                <Badge key={type} variant="outline" className="text-xs">
                  {type}: {iocs[type]?.length || 0}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {generatedQueries.map((query, index) => (
        <Card key={index}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="font-terminal text-sm">{query.template}</CardTitle>
              <div className="flex items-center gap-2">
                <div className={`status-indicator ${getValidationClass(query.validation)}`}>
                  {getValidationIcon(query.validation)}
                  <span className="text-xs font-code">
                    {getValidationStatus(query.validation)}
                  </span>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="relative">
              <Editor
                height="200px"
                defaultLanguage="sql"
                value={query.cql}
                theme="vs-dark"
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  fontSize: 14,
                  fontFamily: 'IBM Plex Mono, monospace'
                }}
              />
            </div>

            {query.validation.errors.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-destructive">Validation Errors:</h4>
                <ul className="text-sm space-y-1">
                  {query.validation.errors.map((error, i) => (
                    <li key={i} className="text-destructive">• {error}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyToClipboard(query.cql)}
                className="gap-2"
              >
                <Copy className="h-4 w-4" />
                Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => downloadQuery(query.cql, query.template)}
                className="gap-2"
              >
                <Download className="h-4 w-4" />
                Download
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled
                className="gap-2"
              >
                <ExternalLink className="h-4 w-4" />
                Open in NG-SIEM
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};