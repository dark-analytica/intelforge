import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { Bot, Copy, Sparkles, BookOpen, Code, Zap, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { vendors, getVendorById, getModuleById, validateFieldMapping } from '@/lib/vendors';

interface CQLBuilderProps {}

export const CQLBuilder = ({}: CQLBuilderProps) => {
  const [query, setQuery] = useState('');
  const [userInput, setUserInput] = useState('');
  const [selectedModel, setSelectedModel] = useState('gpt-5-2025-08-07');
  const [selectedVendor, setSelectedVendor] = useState('');
  const [selectedModule, setSelectedModule] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<{ valid: boolean; missing: string[]; warnings: string[]; } | null>(null);
  const { toast } = useToast();

  const modelOptions = [
    { value: 'gpt-5-2025-08-07', label: 'GPT-5 (2025-08-07)', description: 'Latest flagship model' },
    { value: 'gpt-5-mini-2025-08-07', label: 'GPT-5 Mini (2025-08-07)', description: 'Fast & efficient' },
    { value: 'gpt-5-nano-2025-08-07', label: 'GPT-5 Nano (2025-08-07)', description: 'Fastest model' },
    { value: 'gpt-4.1-2025-04-14', label: 'GPT-4.1 (2025-04-14)', description: 'Reliable flagship' },
    { value: 'o3-2025-04-16', label: 'O3 (2025-04-16)', description: 'Advanced reasoning' },
    { value: 'o4-mini-2025-04-16', label: 'O4 Mini (2025-04-16)', description: 'Fast reasoning' },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini', description: 'Legacy fast model' }
  ];

  const examplePrompts = [
    "Find authentication events with medium to critical risk levels and display in map format",
    "Search for PowerShell executions with encoded commands",
    "Detect suspicious network connections to external IPs", 
    "Find file creation events in system directories",
    "Correlate authentication failures with successful logons",
    "Search for DNS queries to recently registered domains"
  ];

  // Validation function
  const validateQuery = (queryText: string) => {
    if (!selectedVendor || !selectedModule || !queryText.trim()) {
      setValidationResult(null);
      return;
    }

    // Extract potential field references from query
    const fieldMatches = queryText.match(/\b[a-zA-Z_][a-zA-Z0-9_]*\b/g) || [];
    const uniqueFields = [...new Set(fieldMatches)];
    
    const result = validateFieldMapping(selectedVendor, selectedModule, uniqueFields);
    setValidationResult(result);
  };

  const generateCQLQuery = async () => {
    if (!userInput.trim()) {
      toast({
        title: "Input Required",
        description: "Please describe what you want to search for.",
        variant: "destructive"
      });
      return;
    }

    setIsGenerating(true);
    setError(null);

    try {
      const { data, error: functionError } = await supabase.functions.invoke('generate-cql', {
        body: {
          description: userInput,
          model: selectedModel,
          context: "CrowdStrike Falcon LogScale (Humio) environment",
          vendor: selectedVendor || undefined,
          module: selectedModule || undefined
        }
      });

      if (functionError) {
        throw new Error(functionError.message);
      }

      if (data?.query) {
        setQuery(data.query);
        validateQuery(data.query);
        toast({
          title: "Query Generated",
          description: `CQL query generated using ${data.model_used || selectedModel}`
        });
      } else {
        throw new Error('No query received from the generator');
      }
    } catch (err) {
      console.error('CQL generation error:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate CQL query');
      toast({
        title: "Generation Failed",
        description: "Failed to generate CQL query. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Copied",
        description: "Query copied to clipboard."
      });
    } catch (err) {
      toast({
        title: "Copy Failed",
        description: "Failed to copy to clipboard.",
        variant: "destructive"
      });
    }
  };

  const useExamplePrompt = (prompt: string) => {
    setUserInput(prompt);
  };

  // Get available modules for selected vendor
  const availableModules = selectedVendor ? getVendorById(selectedVendor)?.modules || [] : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
          <Bot className="h-4 w-4 text-primary-foreground" />
        </div>
        <div>
          <h2 className="text-xl font-semibold">CQL Query Builder</h2>
          <p className="text-sm text-muted-foreground">
            Generate CQL queries using natural language with AI assistance
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-4 w-4" />
              Query Description
            </CardTitle>
            <CardDescription>
              Describe what you want to search for in natural language
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="vendor-select">Platform/Vendor</Label>
                <Select value={selectedVendor} onValueChange={(value) => { setSelectedVendor(value); setSelectedModule(''); }}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select platform (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    {vendors.map((vendor) => (
                      <SelectItem key={vendor.id} value={vendor.id}>
                        <div className="flex flex-col">
                          <span>{vendor.name}</span>
                          <span className="text-xs text-muted-foreground">{vendor.description}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="module-select">Module</Label>
                <Select 
                  value={selectedModule} 
                  onValueChange={setSelectedModule}
                  disabled={!selectedVendor}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select module (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    {availableModules.map((module) => (
                      <SelectItem key={module.id} value={module.id}>
                        <div className="flex flex-col">
                          <span>{module.name}</span>
                          <span className="text-xs text-muted-foreground">{module.description}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="model-select">AI Model</Label>
              <Select value={selectedModel} onValueChange={setSelectedModel}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {modelOptions.map((model) => (
                    <SelectItem key={model.value} value={model.value}>
                      <div className="flex flex-col">
                        <span>{model.label}</span>
                        <span className="text-xs text-muted-foreground">{model.description}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="user-input">Description</Label>
              <Textarea
                id="user-input"
                placeholder="Example: Find all PowerShell executions with encoded commands in the last 24 hours"
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                rows={4}
              />
            </div>

            <div className="space-y-3">
              <Label>Example Prompts</Label>
              <div className="flex flex-wrap gap-2">
                {examplePrompts.map((prompt, index) => (
                  <Badge
                    key={index}
                    variant="outline"
                    className="cursor-pointer hover:bg-primary/10"
                    onClick={() => useExamplePrompt(prompt)}
                  >
                    {prompt}
                  </Badge>
                ))}
              </div>
            </div>

            <Button
              onClick={generateCQLQuery}
              disabled={isGenerating || !userInput.trim()}
              className="w-full gap-2"
            >
              <Bot className="h-4 w-4" />
              {isGenerating ? 'Generating...' : 'Generate CQL Query'}
            </Button>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>

        {/* Output Section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Code className="h-4 w-4" />
              Generated Query
            </CardTitle>
            <CardDescription>
              Ready-to-use CQL query for LogScale/Humio
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>CQL Query</Label>
                {query && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard(query)}
                    className="gap-2"
                  >
                    <Copy className="h-3 w-3" />
                    Copy
                  </Button>
                )}
              </div>
              <Textarea
                value={query}
                onChange={(e) => { setQuery(e.target.value); validateQuery(e.target.value); }}
                placeholder="Generated CQL query will appear here..."
                rows={12}
                className="font-mono text-sm"
              />
            </div>

            {validationResult && (
              <div className="space-y-2">
                <Label>Validation Results</Label>
                <Alert variant={validationResult.valid ? "default" : "destructive"}>
                  <div className="flex items-center gap-2">
                    {validationResult.valid ? (
                      <CheckCircle2 className="h-4 w-4 text-green-600" />
                    ) : (
                      <AlertTriangle className="h-4 w-4" />
                    )}
                    <span className="font-medium">
                      {validationResult.valid ? 'Query validation passed' : 'Query validation issues found'}
                    </span>
                  </div>
                  {!validationResult.valid && validationResult.missing.length > 0 && (
                    <div className="mt-2">
                      <p className="text-sm font-medium mb-1">Missing field mappings:</p>
                      <div className="flex flex-wrap gap-1">
                        {validationResult.missing.map((field) => (
                          <Badge key={field} variant="destructive" className="text-xs">
                            {field}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {validationResult.warnings.length > 0 && (
                    <div className="mt-2">
                      <p className="text-sm font-medium mb-1">Warnings:</p>
                      <ul className="text-xs text-muted-foreground list-disc list-inside">
                        {validationResult.warnings.map((warning, index) => (
                          <li key={index}>{warning}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </Alert>
              </div>
            )}

            {query && (
              <div className="space-y-2">
                <Button
                  variant="outline"
                  onClick={() => copyToClipboard(query)}
                  className="w-full gap-2"
                >
                  <Copy className="h-4 w-4" />
                  Copy Query to Clipboard
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Documentation Quick Reference */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="h-4 w-4" />
            Quick Reference
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="space-y-2">
              <h4 className="font-medium">Common Operators</h4>
              <div className="text-sm text-muted-foreground space-y-1">
                <div><code>=</code> - Exact match</div>
                <div><code>!=</code> - Not equal</div>
                <div><code>~</code> - Regex match</div>
                <div><code>in()</code> - Value in list</div>
              </div>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium">Time Functions</h4>
              <div className="text-sm text-muted-foreground space-y-1">
                <div><code>@timestamp</code> - Event time</div>
                <div><code>bucket()</code> - Time grouping</div>
                <div><code>now()</code> - Current time</div>
                <div><code>-1d</code> - Relative time</div>
              </div>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium">Aggregations</h4>
              <div className="text-sm text-muted-foreground space-y-1">
                <div><code>count()</code> - Count events</div>
                <div><code>groupBy()</code> - Group results</div>
                <div><code>stats()</code> - Statistics</div>
                <div><code>sort()</code> - Sort results</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};