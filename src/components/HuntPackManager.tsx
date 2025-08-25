import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { 
  huntPacks, 
  getHuntPacksByTactic, 
  getHuntPacksByDifficulty, 
  searchHuntPacks,
  type HuntPack,
  type HuntQuery
} from '@/lib/hunt-packs';
import { 
  Search, 
  ChevronDown, 
  ChevronUp, 
  Package, 
  Target, 
  Copy, 
  ExternalLink, 
  Zap, 
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface HuntPackManagerProps {
  onApplyQuery?: (query: string, huntId: string) => void;
}

export const HuntPackManager = ({ onApplyQuery }: HuntPackManagerProps) => {
  const [selectedTactic, setSelectedTactic] = useState<string>('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedPacks, setExpandedPacks] = useState<Set<string>>(new Set());
  const { toast } = useToast();

  const allTactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
                     'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 
                     'Collection', 'Command and Control', 'Exfiltration', 'Impact'];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
      case 'intermediate': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'advanced': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200';
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200';
    }
  };

  const togglePack = (packId: string) => {
    const newExpanded = new Set(expandedPacks);
    if (newExpanded.has(packId)) {
      newExpanded.delete(packId);
    } else {
      newExpanded.add(packId);
    }
    setExpandedPacks(newExpanded);
  };

  const copyQuery = async (query: string, queryName: string) => {
    await navigator.clipboard.writeText(query);
    toast({
      title: "Query Copied",
      description: `"${queryName}" copied to clipboard`
    });
  };

  const getFilteredPacks = (): HuntPack[] => {
    let filtered = huntPacks;

    if (selectedTactic !== 'all') {
      filtered = getHuntPacksByTactic(selectedTactic);
    }

    if (selectedDifficulty !== 'all') {
      filtered = getHuntPacksByDifficulty(selectedDifficulty as any);
    }

    if (searchQuery.trim()) {
      filtered = searchHuntPacks(searchQuery).filter(pack => 
        selectedTactic === 'all' || pack.tactics.includes(selectedTactic)
      ).filter(pack =>
        selectedDifficulty === 'all' || pack.difficulty === selectedDifficulty
      );
    }

    return filtered;
  };

  const filteredPacks = getFilteredPacks();

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            TTP-First Hunt Packs
          </CardTitle>
          <CardDescription>
            Pre-built hunt templates organized by MITRE ATT&CK tactics and techniques
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Alert>
            <Shield className="h-4 w-4" />
            <AlertDescription>
              <strong>{huntPacks.length} hunt packs</strong> available with {huntPacks.reduce((sum, pack) => sum + pack.queries.length, 0)} total queries. 
              Focus on TTP-based hunts for maximum impact on adversary operations.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Filters & Search</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Search</label>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search hunt packs..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Tactic</label>
              <Select value={selectedTactic} onValueChange={setSelectedTactic}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Tactics</SelectItem>
                  {allTactics.map(tactic => (
                    <SelectItem key={tactic} value={tactic}>{tactic}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Difficulty</label>
              <Select value={selectedDifficulty} onValueChange={setSelectedDifficulty}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="beginner">Beginner</SelectItem>
                  <SelectItem value="intermediate">Intermediate</SelectItem>
                  <SelectItem value="advanced">Advanced</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <Badge variant="secondary">
              {filteredPacks.length} pack{filteredPacks.length !== 1 ? 's' : ''} found
            </Badge>
            <Badge variant="outline">
              {filteredPacks.reduce((sum, pack) => sum + pack.queries.length, 0)} total queries
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Hunt Packs */}
      <div className="space-y-4">
        {filteredPacks.length === 0 ? (
          <Card>
            <CardContent className="pt-6">
              <div className="text-center text-muted-foreground">
                <Package className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <h3 className="font-medium mb-2">No Hunt Packs Found</h3>
                <p className="text-sm">Try adjusting your filters or search terms</p>
              </div>
            </CardContent>
          </Card>
        ) : (
          filteredPacks.map((pack) => (
            <Card key={pack.id} className="overflow-hidden">
              <Collapsible
                open={expandedPacks.has(pack.id)}
                onOpenChange={() => togglePack(pack.id)}
              >
                <CollapsibleTrigger asChild>
                  <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center gap-3">
                          <CardTitle className="text-lg">{pack.name}</CardTitle>
                          <Badge className={getDifficultyColor(pack.difficulty)}>
                            {pack.difficulty}
                          </Badge>
                          <Badge variant="outline">
                            {pack.queries.length} queries
                          </Badge>
                        </div>
                        <CardDescription>{pack.description}</CardDescription>
                        
                        <div className="flex flex-wrap gap-2">
                          {pack.tactics.map(tactic => (
                            <Badge key={tactic} variant="secondary" className="text-xs">
                              {tactic}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      {expandedPacks.has(pack.id) ? 
                        <ChevronUp className="h-4 w-4 mt-1" /> : 
                        <ChevronDown className="h-4 w-4 mt-1" />
                      }
                    </div>
                  </CardHeader>
                </CollapsibleTrigger>

                <CollapsibleContent>
                  <CardContent className="pt-0">
                    <Tabs defaultValue="queries">
                      <TabsList>
                        <TabsTrigger value="queries">Queries ({pack.queries.length})</TabsTrigger>
                        <TabsTrigger value="metadata">Metadata</TabsTrigger>
                      </TabsList>

                      <TabsContent value="queries" className="space-y-4">
                        {pack.queries.map((query) => (
                          <Card key={query.id} className="bg-muted/30">
                            <CardHeader>
                              <div className="flex items-start justify-between">
                                <div>
                                  <div className="flex items-center gap-2 mb-2">
                                    <CardTitle className="text-base">{query.name}</CardTitle>
                                    <Badge className={getConfidenceColor(query.confidence)}>
                                      {query.confidence}
                                    </Badge>
                                  </div>
                                  <CardDescription>{query.description}</CardDescription>
                                </div>
                              </div>
                            </CardHeader>
                            <CardContent className="space-y-4">
                              <div className="space-y-2">
                                <h5 className="text-sm font-medium">MITRE ATT&CK Techniques</h5>
                                <div className="flex flex-wrap gap-1">
                                  {query.techniques.map(technique => (
                                    <Button
                                      key={technique}
                                      variant="outline"
                                      size="sm"
                                      className="h-6 px-2 text-xs"
                                      asChild
                                    >
                                      <a
                                        href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-1"
                                      >
                                        {technique}
                                        <ExternalLink className="h-3 w-3" />
                                      </a>
                                    </Button>
                                  ))}
                                </div>
                              </div>

                              <div className="space-y-2">
                                <h5 className="text-sm font-medium">Data Sources</h5>
                                <div className="flex flex-wrap gap-1">
                                  {query.data_sources.map(source => (
                                    <Badge key={source} variant="outline" className="text-xs">
                                      {source}
                                    </Badge>
                                  ))}
                                </div>
                              </div>

                              <Separator />

                              <div className="space-y-2">
                                <h5 className="text-sm font-medium">Hunt Query</h5>
                                <div className="bg-background rounded-md p-3 font-mono text-sm border">
                                  <pre className="whitespace-pre-wrap text-xs">{query.query}</pre>
                                </div>
                              </div>

                              <div className="flex gap-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => copyQuery(query.query, query.name)}
                                  className="gap-2"
                                >
                                  <Copy className="h-4 w-4" />
                                  Copy Query
                                </Button>
                                {onApplyQuery && (
                                  <Button
                                    size="sm"
                                    onClick={() => onApplyQuery(query.query, query.id)}
                                    className="gap-2"
                                  >
                                    <Zap className="h-4 w-4" />
                                    Apply to Builder
                                  </Button>
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </TabsContent>

                      <TabsContent value="metadata" className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <h5 className="text-sm font-medium">Associated Threat Actors</h5>
                            <div className="flex flex-wrap gap-1">
                              {pack.metadata.threat_actors?.map(actor => (
                                <Badge key={actor} variant="destructive" className="text-xs">
                                  {actor}
                                </Badge>
                              )) || <span className="text-sm text-muted-foreground">Not specified</span>}
                            </div>
                          </div>

                          <div className="space-y-2">
                            <h5 className="text-sm font-medium">Target Industries</h5>
                            <div className="flex flex-wrap gap-1">
                              {pack.metadata.industries?.map(industry => (
                                <Badge key={industry} variant="secondary" className="text-xs">
                                  {industry}
                                </Badge>
                              )) || <span className="text-sm text-muted-foreground">All industries</span>}
                            </div>
                          </div>

                          <div className="space-y-2">
                            <h5 className="text-sm font-medium">Platforms</h5>
                            <div className="flex flex-wrap gap-1">
                              {pack.metadata.platforms?.map(platform => (
                                <Badge key={platform} variant="outline" className="text-xs">
                                  {platform}
                                </Badge>
                              )) || <span className="text-sm text-muted-foreground">Cross-platform</span>}
                            </div>
                          </div>

                          <div className="space-y-2">
                            <h5 className="text-sm font-medium flex items-center gap-1">
                              <Clock className="h-4 w-4" />
                              Last Updated
                            </h5>
                            <p className="text-sm text-muted-foreground">
                              {pack.metadata.last_updated}
                            </p>
                          </div>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </CollapsibleContent>
              </Collapsible>
            </Card>
          ))
        )}
      </div>
    </div>
  );
};