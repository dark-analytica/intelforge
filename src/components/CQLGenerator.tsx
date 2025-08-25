import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cqlTemplates, renderTemplateWithVendor, validateCQLSyntax } from '@/lib/cql-templates';
import { type IOCSet } from '@/lib/ioc-extractor';
import { Copy, Download, ExternalLink, CheckCircle, AlertTriangle, XCircle, Sparkles } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { VendorPicker } from './VendorPicker';
import Editor from '@monaco-editor/react';

interface CQLGeneratorProps {
  iocs: IOCSet;
  onQueriesGenerated?: (queries: string[]) => void;
}

interface GeneratedQuery {
  template: string;
  cql: string;
  validation: any;
  vendor: string;
  module: string;
  warnings: string[];
  timestamp: Date;
}

export const CQLGenerator = ({ iocs, onQueriesGenerated }: CQLGeneratorProps) => {
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const [selectedVendor, setSelectedVendor] = useState('crowdstrike');
  const [selectedModule, setSelectedModule] = useState('falcon-data-replicator');
  const [generatedQueries, setGeneratedQueries] = useState<GeneratedQuery[]>([]);
  const [filterRepo, setFilterRepo] = useState<string>('all');
  const { toast } = useToast();

  const generateQueries = () => {
    if (!selectedTemplateId || !selectedVendor || !selectedModule) return;

    const template = cqlTemplates.find(t => t.id === selectedTemplateId);
    if (!template) return;

    // Use vendor-aware rendering
    const { query: cql, profile, warnings } = renderTemplateWithVendor(
      template, 
      iocs, 
      selectedVendor, 
      selectedModule
    );
    
    const validation = validateCQLSyntax(cql);

    const newQuery: GeneratedQuery = {
      template: template.name,
      cql,
      validation,
      vendor: selectedVendor,
      module: selectedModule,
      warnings,
      timestamp: new Date()
    };

    setGeneratedQueries(prev => [newQuery, ...prev.slice(0, 9)]); // Keep last 10 queries
    onQueriesGenerated?.([cql, ...generatedQueries.map(q => q.cql)]);
    
    toast({
      title: "Query Generated",
      description: `${template.name} generated for ${profile.name}`
    });
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
      return <CheckCircle className="h-4 w-4 text-green-600" />;
    } else if (validation.errors.length > 0) {
      return <XCircle className="h-4 w-4 text-red-600" />;
    }
    return <AlertTriangle className="h-4 w-4 text-amber-600" />;
  };

  const getValidationStatus = (validation: any) => {
    if (validation.valid) return 'VALID ✓';
    if (validation.errors.length > 0) return 'INVALID ✖';
    return 'WARNING ⚠';
  };

  // Filter templates by repository type
  const filteredTemplates = filterRepo === 'all' 
    ? cqlTemplates 
    : cqlTemplates.filter(t => t.repo === filterRepo);

  const hasRequiredIOCs = (templateId: string) => {
    const tpl = cqlTemplates.find(t => t.id === templateId);
    if (!tpl || tpl.requiredIOCTypes.length === 0) return true; // Templates with no required IOCs are always available
    return tpl.requiredIOCTypes.some((type) => (iocs as any)[type]?.length > 0);
  };

  const getTemplateCategories = () => {
    const categories = [...new Set(cqlTemplates.map(t => t.repo))];
    return categories.map(cat => ({
      value: cat,
      label: cat.charAt(0).toUpperCase() + cat.slice(1),
      count: cqlTemplates.filter(t => t.repo === cat).length
    }));
  };

  const selectedTemplate = cqlTemplates.find(t => t.id === selectedTemplateId);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="font-terminal text-glow flex items-center gap-2">
            <Sparkles className="h-5 w-5" />
            Vendor-Aware CQL Generator
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Vendor Configuration */}
          <VendorPicker
            selectedVendor={selectedVendor}
            selectedModule={selectedModule}
            onVendorChange={setSelectedVendor}
            onModuleChange={setSelectedModule}
            generatedQuery={generatedQueries[0]?.cql}
          />

          {/* Template Selection */}
          <div className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-1">
                <label className="text-sm font-medium mb-2 block">Template Category</label>
                <Select value={filterRepo} onValueChange={setFilterRepo}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Categories ({cqlTemplates.length})</SelectItem>
                    {getTemplateCategories().map(cat => (
                      <SelectItem key={cat.value} value={cat.value}>
                        {cat.label} ({cat.count})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              
              <div className="flex-2">
                <label className="text-sm font-medium mb-2 block">CQL Template</label>
                <Select value={selectedTemplateId} onValueChange={setSelectedTemplateId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a CQL template..." />
                  </SelectTrigger>
                  <SelectContent>
                    {filteredTemplates.map(template => (
                      <SelectItem key={template.id} value={template.id}>
                        <div className="flex flex-col">
                          <span>{template.name}</span>
                          <span className="text-xs text-muted-foreground">{template.description}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {selectedTemplate && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline" className="text-xs">
                      {selectedTemplate.repo}
                    </Badge>
                    {selectedTemplate.requiredIOCTypes.map(type => (
                      <Badge 
                        key={type} 
                        variant={iocs[type as keyof IOCSet]?.length > 0 ? "default" : "secondary"}
                        className="text-xs"
                      >
                        {type}: {iocs[type as keyof IOCSet]?.length || 0}
                      </Badge>
                    ))}
                  </div>
                  
                  <Button 
                    onClick={generateQueries}
                    disabled={!selectedTemplateId || !hasRequiredIOCs(selectedTemplateId) || !selectedVendor || !selectedModule}
                    className="gap-2"
                  >
                    <Sparkles className="h-4 w-4" />
                    Generate CQL
                  </Button>
                </div>

                {selectedTemplate.requiredIOCTypes.length > 0 && !hasRequiredIOCs(selectedTemplateId) && (
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      This template requires IOCs of type: {selectedTemplate.requiredIOCTypes.join(', ')}. 
                      Extract matching IOCs first.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Generated Queries */}
      {generatedQueries.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="font-terminal text-glow">Generated Queries ({generatedQueries.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="0" className="w-full">
              <TabsList className="grid w-full grid-cols-5">
                {generatedQueries.slice(0, 5).map((_, index) => (
                  <TabsTrigger key={index} value={index.toString()} className="text-xs">
                    Query {index + 1}
                  </TabsTrigger>
                ))}
              </TabsList>

              {generatedQueries.slice(0, 5).map((query, index) => (
                <TabsContent key={index} value={index.toString()} className="mt-4">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <h4 className="font-medium">{query.template}</h4>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <span>{query.vendor} • {query.module}</span>
                          <span>•</span>
                          <span>{query.timestamp.toLocaleTimeString()}</span>
                          <div className="flex items-center gap-1">
                            {getValidationIcon(query.validation)}
                            <span>{getValidationStatus(query.validation)}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {query.warnings.length > 0 && (
                      <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>
                          <div className="space-y-1">
                            <p className="font-medium">Field Mapping Warnings:</p>
                            <ul className="text-xs space-y-1">
                              {query.warnings.map((warning, i) => (
                                <li key={i}>• {warning}</li>
                              ))}
                            </ul>
                          </div>
                        </AlertDescription>
                      </Alert>
                    )}

                    <div className="relative">
                      <Editor
                        height="250px"
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
                      <Alert variant="destructive">
                        <XCircle className="h-4 w-4" />
                        <AlertDescription>
                          <div className="space-y-1">
                            <p className="font-medium">Validation Errors:</p>
                            <ul className="text-sm space-y-1">
                              {query.validation.errors.map((error, i) => (
                                <li key={i}>• {error}</li>
                              ))}
                            </ul>
                          </div>
                        </AlertDescription>
                      </Alert>
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
                        Open in {query.vendor}
                      </Button>
                    </div>
                  </div>
                </TabsContent>
              ))}
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
};