import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { Textarea } from './ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Alert, AlertDescription } from './ui/alert';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from './ui/collapsible';
import { 
  BarChart3, 
  AlertTriangle, 
  CheckCircle, 
  Zap, 
  TrendingUp, 
  ChevronDown,
  ChevronRight,
  Download,
  Play
} from 'lucide-react';
import { cqlAnalyzer, type CQLAnalysisResult } from '../lib/cql-analyzer';

interface QueryAnalyzerProps {
  queries?: string[];
  onOptimizedQuery?: (originalQuery: string, optimizedQuery: string) => void;
}

export const QueryAnalyzer = ({ queries = [], onOptimizedQuery }: QueryAnalyzerProps) => {
  const [inputQuery, setInputQuery] = useState('');
  const [analysisResults, setAnalysisResults] = useState<CQLAnalysisResult[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [expandedResults, setExpandedResults] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (queries.length > 0) {
      analyzeQueries(queries);
    }
  }, [queries]);

  const analyzeQueries = async (queriesToAnalyze: string[]) => {
    setIsAnalyzing(true);
    try {
      // Simulate async analysis for better UX
      await new Promise(resolve => setTimeout(resolve, 500));
      const results = cqlAnalyzer.analyzeBatch(queriesToAnalyze);
      setAnalysisResults(results);
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyzeInput = () => {
    if (inputQuery.trim()) {
      analyzeQueries([inputQuery.trim()]);
    }
  };

  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedResults);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedResults(newExpanded);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getScoreVariant = (score: number) => {
    if (score >= 80) return 'default';
    if (score >= 60) return 'secondary';
    return 'destructive';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      default: return 'outline';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'destructive';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      default: return 'outline';
    }
  };

  const generateReport = () => {
    if (analysisResults.length === 0) return;
    
    const report = cqlAnalyzer.generateReport(analysisResults);
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cql-performance-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const avgScore = analysisResults.length > 0 
    ? analysisResults.reduce((sum, r) => sum + r.performanceScore, 0) / analysisResults.length 
    : 0;

  const totalIssues = analysisResults.reduce((sum, r) => sum + r.issues.length, 0);
  const criticalIssues = analysisResults.reduce((sum, r) => 
    sum + r.issues.filter(i => i.severity === 'critical').length, 0);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Query Performance Analyzer
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Analyze Custom Query</label>
            <Textarea
              placeholder="Paste your query here for performance analysis..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              className="min-h-[100px] font-mono text-sm"
            />
            <Button 
              onClick={handleAnalyzeInput} 
              disabled={!inputQuery.trim() || isAnalyzing}
              className="w-full"
            >
              <Play className="h-4 w-4 mr-2" />
              {isAnalyzing ? 'Analyzing...' : 'Analyze Query'}
            </Button>
          </div>

          {analysisResults.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-muted rounded-lg">
              <div className="text-center">
                <div className={`text-2xl font-bold ${getScoreColor(avgScore)}`}>
                  {avgScore.toFixed(1)}
                </div>
                <div className="text-sm text-muted-foreground">Avg Performance Score</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{totalIssues}</div>
                <div className="text-sm text-muted-foreground">Total Issues</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{criticalIssues}</div>
                <div className="text-sm text-muted-foreground">Critical Issues</div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {analysisResults.length > 0 && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Analysis Results</CardTitle>
            <Button variant="outline" size="sm" onClick={generateReport}>
              <Download className="h-4 w-4 mr-2" />
              Export Report
            </Button>
          </CardHeader>
          <CardContent className="space-y-4">
            {analysisResults.map((result, index) => (
              <Card key={index} className="border-l-4 border-l-blue-500">
                <Collapsible>
                  <CollapsibleTrigger 
                    className="w-full"
                    onClick={() => toggleExpanded(index)}
                  >
                    <CardHeader className="flex flex-row items-center justify-between hover:bg-muted/50 transition-colors">
                      <div className="flex items-center gap-3">
                        {expandedResults.has(index) ? 
                          <ChevronDown className="h-4 w-4" /> : 
                          <ChevronRight className="h-4 w-4" />
                        }
                        <div className="text-left">
                          <div className="font-medium">Query {index + 1}</div>
                          <div className="text-sm text-muted-foreground truncate max-w-[300px]">
                            {result.query.substring(0, 60)}...
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getScoreVariant(result.performanceScore)}>
                          {result.performanceScore}/100
                        </Badge>
                        <Badge variant="outline" className="capitalize">
                          {result.complexity}
                        </Badge>
                        <Badge variant={result.estimatedImpact === 'high' ? 'destructive' : 'secondary'}>
                          {result.estimatedImpact} impact
                        </Badge>
                      </div>
                    </CardHeader>
                  </CollapsibleTrigger>
                  
                  <CollapsibleContent>
                    <CardContent className="pt-0">
                      <Tabs defaultValue="issues" className="w-full">
                        <TabsList className="grid w-full grid-cols-3">
                          <TabsTrigger value="issues">
                            Issues ({result.issues.length})
                          </TabsTrigger>
                          <TabsTrigger value="optimizations">
                            Optimizations ({result.optimizations.length})
                          </TabsTrigger>
                          <TabsTrigger value="query">Query</TabsTrigger>
                        </TabsList>

                        <TabsContent value="issues" className="space-y-3">
                          {result.issues.length === 0 ? (
                            <Alert>
                              <CheckCircle className="h-4 w-4" />
                              <AlertDescription>
                                No performance issues detected in this query.
                              </AlertDescription>
                            </Alert>
                          ) : (
                            result.issues.map((issue, issueIndex) => (
                              <Alert key={issueIndex}>
                                <AlertTriangle className="h-4 w-4" />
                                <AlertDescription>
                                  <div className="flex items-start justify-between">
                                    <div className="space-y-1">
                                      <div className="flex items-center gap-2">
                                        <Badge variant={getSeverityColor(issue.severity)}>
                                          {issue.severity}
                                        </Badge>
                                        <span className="font-medium">{issue.description}</span>
                                      </div>
                                      <div className="text-sm text-muted-foreground">
                                        Location: {issue.location}
                                      </div>
                                      <div className="text-sm">
                                        Impact: {issue.impact}
                                      </div>
                                    </div>
                                  </div>
                                </AlertDescription>
                              </Alert>
                            ))
                          )}
                        </TabsContent>

                        <TabsContent value="optimizations" className="space-y-3">
                          {result.optimizations.length === 0 ? (
                            <Alert>
                              <CheckCircle className="h-4 w-4" />
                              <AlertDescription>
                                No specific optimizations suggested for this query.
                              </AlertDescription>
                            </Alert>
                          ) : (
                            result.optimizations.map((opt, optIndex) => (
                              <Card key={optIndex} className="p-4">
                                <div className="space-y-3">
                                  <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                      <Badge variant={getPriorityColor(opt.priority)}>
                                        {opt.priority} priority
                                      </Badge>
                                      <TrendingUp className="h-4 w-4 text-green-600" />
                                    </div>
                                  </div>
                                  <div className="space-y-2">
                                    <div className="font-medium">{opt.description}</div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                      <div>
                                        <div className="font-medium text-red-600 mb-1">Before:</div>
                                        <code className="bg-red-50 p-2 rounded text-xs block">
                                          {opt.before}
                                        </code>
                                      </div>
                                      <div>
                                        <div className="font-medium text-green-600 mb-1">After:</div>
                                        <code className="bg-green-50 p-2 rounded text-xs block">
                                          {opt.after}
                                        </code>
                                      </div>
                                    </div>
                                    <div className="text-sm text-muted-foreground">
                                      <Zap className="h-3 w-3 inline mr-1" />
                                      Expected improvement: {opt.expectedImprovement}
                                    </div>
                                  </div>
                                </div>
                              </Card>
                            ))
                          )}
                        </TabsContent>

                        <TabsContent value="query">
                          <div className="space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="font-medium">Original Query</span>
                              <div className="flex items-center gap-2">
                                <span className="text-sm text-muted-foreground">Performance Score:</span>
                                <Progress 
                                  value={result.performanceScore} 
                                  className="w-24 h-2" 
                                />
                                <span className={`font-medium ${getScoreColor(result.performanceScore)}`}>
                                  {result.performanceScore}/100
                                </span>
                              </div>
                            </div>
                            <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto">
                              <code>{result.query}</code>
                            </pre>
                          </div>
                        </TabsContent>
                      </Tabs>
                    </CardContent>
                  </CollapsibleContent>
                </Collapsible>
              </Card>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
