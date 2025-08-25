import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Download, Copy } from 'lucide-react';
import { IOCSet } from '@/lib/ioc-extractor';
import { exportToCQL, exportToCSV, exportToSTIX, exportToJSON, downloadFile } from '@/lib/exporters';
import { useToast } from '@/hooks/use-toast';

interface ExportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  iocs: IOCSet;
  queries?: any[];
  ttps?: any[];
  detections?: any[];
  entities?: any;
}

export const ExportDialog = ({ 
  open, 
  onOpenChange, 
  iocs, 
  queries = [], 
  ttps = [], 
  detections = [],
  entities = null 
}: ExportDialogProps) => {
  const { toast } = useToast();

  // Enhanced export data with Phase 4 features
  const exportData = {
    meta: {
      source_title: "CTI Analysis Report",
      tlp: "GREEN",
      generated_at: new Date().toISOString()
    },
    iocs,
    ttps: ttps.map(ttp => ttp.technique_id || 'Unknown'),
    profile: `${queries[0]?.vendor || 'Mixed'} - ${queries[0]?.module || 'Mixed'}`,
    queries: {
      cql: queries.map(q => q.cql || q)
    }
  };

  // Statistics for the summary
  const stats = {
    totalIOCs: Object.values(iocs).reduce((sum, arr) => sum + arr.length, 0),
    totalTTPs: ttps.length,
    totalDetections: detections.length,
    totalQueries: queries.length,
    hasAIAnalysis: ttps.length > 0 || detections.length > 0
  };

  // Enhanced export content with TTP and detection context
  const createEnhancedCQL = () => {
    if (queries.length === 0) return 'No CQL queries available for export';
    
    let content = `-- CQL Query Bundle with AI Analysis
-- Generated: ${new Date().toISOString()}
-- Total Queries: ${queries.length}
-- TTPs Identified: ${ttps.length}
-- Detections Generated: ${detections.length}
-- 
-- This bundle contains CQL queries enhanced with MITRE ATT&CK context

`;

    queries.forEach((query, index) => {
      const relatedTTPs = ttps.filter(ttp => 
        query.template && ttp.behavior && 
        ttp.behavior.toLowerCase().includes(query.template.toLowerCase().split(' ')[0])
      );
      
      content += `-- Query ${index + 1}: ${query.template || 'Untitled Query'}
-- Vendor: ${query.vendor || 'Unknown'} (${query.module || 'Unknown'})
-- Status: ${query.validation?.valid ? 'VALID' : 'NEEDS_REVIEW'}
${relatedTTPs.length > 0 ? `-- Related TTPs: ${relatedTTPs.map(t => t.technique_id).join(', ')}\n` : ''}
${query.cql || query}

`;
    });
    
    return content;
  };

  const createEnhancedCSV = () => {
    let csv = 'type,value,confidence,context,technique_id,tactic,behavior,data_sources,first_seen,notes\n';
    
    Object.entries(iocs).forEach(([type, iocList]) => {
      iocList.forEach(ioc => {
        // Find related TTPs for this IOC
        const relatedTTPs = ttps.filter(ttp => 
          ttp.evidence_excerpt && ttp.evidence_excerpt.toLowerCase().includes(ioc.toLowerCase())
        );
        
        // Find related detections
        const relatedDetections = detections.filter(detection => 
          detection.suggested_query_snippets && 
          detection.suggested_query_snippets.some(snippet => 
            snippet.toLowerCase().includes(ioc.toLowerCase())
          )
        );
        
        if (relatedTTPs.length > 0) {
          relatedTTPs.forEach(ttp => {
            const detection = relatedDetections[0];
            csv += `${type},"${ioc}",high,ai_derived,${ttp.technique_id || ''},"${ttp.tactic || ''}","${(ttp.behavior || '').replace(/"/g, '""')}","${detection ? detection.data_sources.join(';') : ''}",${exportData.meta.generated_at},"AI-identified TTP"\n`;
          });
        } else {
          csv += `${type},"${ioc}",medium,extracted,,,,,${exportData.meta.generated_at},"Extracted from CTI text"\n`;
        }
      });
    });
    
    return csv;
  };

  const createEnhancedSTIX = () => {
    const bundle = {
      type: "bundle",
      id: `bundle--${crypto.randomUUID()}`,
      spec_version: "2.1",
      objects: []
    };
    
    // Add report object
    const report = {
      type: "report",
      id: `report--${crypto.randomUUID()}`,
      created: exportData.meta.generated_at,
      modified: exportData.meta.generated_at,
      name: exportData.meta.source_title,
      description: `Comprehensive threat intelligence analysis with ${stats.totalIOCs} IOCs and ${stats.totalTTPs} TTPs`,
      published: exportData.meta.generated_at,
      object_refs: [],
      labels: ["threat-report", "ioc-analysis"]
    };
    
    // Add indicators
    Object.entries(iocs).forEach(([type, iocList]) => {
      iocList.forEach(ioc => {
        let pattern = '';
        switch (type) {
          case 'ipv4':
          case 'ipv6':
            pattern = `[ipv4-addr:value = '${ioc}']`;
            break;
          case 'domains':
            pattern = `[domain-name:value = '${ioc}']`;
            break;
          case 'urls':
            pattern = `[url:value = '${ioc}']`;
            break;
          case 'sha256':
            pattern = `[file:hashes.'SHA-256' = '${ioc}']`;
            break;
          case 'md5':
            pattern = `[file:hashes.MD5 = '${ioc}']`;
            break;
          case 'emails':
            pattern = `[email-addr:value = '${ioc}']`;
            break;
        }
        
        if (pattern) {
          const indicatorId = `indicator--${crypto.randomUUID()}`;
          bundle.objects.push({
            type: "indicator",
            id: indicatorId,
            created: exportData.meta.generated_at,
            modified: exportData.meta.generated_at,
            pattern,
            labels: ["malicious-activity"],
            valid_from: exportData.meta.generated_at
          });
          report.object_refs.push(indicatorId);
        }
      });
    });
    
    // Add attack patterns for TTPs
    ttps.forEach(ttp => {
      const attackPatternId = `attack-pattern--${crypto.randomUUID()}`;
      bundle.objects.push({
        type: "attack-pattern",
        id: attackPatternId,
        created: exportData.meta.generated_at,
        modified: exportData.meta.generated_at,
        name: ttp.behavior || 'Unknown Behavior',
        description: ttp.evidence_excerpt || '',
        external_references: [
          {
            source_name: "mitre-attack",
            external_id: ttp.technique_id,
            url: `https://attack.mitre.org/techniques/${ttp.technique_id.replace('.', '/')}/`
          }
        ]
      });
      report.object_refs.push(attackPatternId);
    });
    
    bundle.objects.push(report);
    return JSON.stringify(bundle, null, 2);
  };

  const createEnhancedJSON = () => {
    const enhancedData = {
      ...exportData,
      ai_analysis: {
        ttps: ttps,
        detections: detections,
        entities: entities
      },
      export_metadata: {
        format_version: "2.0",
        exported_at: new Date().toISOString(),
        features: [
          "ioc_extraction",
          "ttp_analysis", 
          "mitre_attack_mapping",
          "vendor_aware_queries",
          "detection_suggestions"
        ]
      },
      statistics: {
        total_iocs: stats.totalIOCs,
        total_ttps: stats.totalTTPs,
        total_detections: stats.totalDetections,
        total_queries: stats.totalQueries,
        ioc_breakdown: Object.fromEntries(
          Object.entries(iocs).map(([type, arr]) => [type, arr.length])
        )
      }
    };
    
    return JSON.stringify(enhancedData, null, 2);
  };

  // Export content
  const cqlContent = createEnhancedCQL();
  const csvContent = createEnhancedCSV();
  const stixContent = createEnhancedSTIX();
  const jsonContent = createEnhancedJSON();

  const handleCopy = async (content: string, format: string) => {
    try {
      await navigator.clipboard.writeText(content);
      toast({
        title: "Copied to clipboard",
        description: `${format} content copied successfully`
      });
    } catch (error) {
      toast({
        title: "Copy failed",
        description: "Failed to copy content to clipboard",
        variant: "destructive"
      });
    }
  };

  const handleDownload = (content: string, filename: string, mimeType: string) => {
    downloadFile(content, filename, mimeType);
    toast({
      title: "Download started",
      description: `${filename} download initiated`
    });
  };

  const ExportCard = ({ 
    title, 
    description, 
    content, 
    filename, 
    mimeType,
    stats 
  }: { 
    title: string; 
    description: string; 
    content: string; 
    filename: string; 
    mimeType: string;
    stats?: { label: string; value: string }[];
  }) => (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
        {stats && (
          <div className="flex flex-wrap gap-2 mt-2">
            {stats.map((stat, i) => (
              <Badge key={i} variant="secondary" className="text-xs">
                {stat.label}: {stat.value}
              </Badge>
            ))}
          </div>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="bg-muted rounded-lg p-4 max-h-48 overflow-auto">
          <pre className="text-xs whitespace-pre-wrap font-mono">
            {content.substring(0, 500)}
            {content.length > 500 && '\n\n... (truncated for preview)'}
          </pre>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleCopy(content, title)}
            className="gap-2"
          >
            <Copy className="h-4 w-4" />
            Copy
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleDownload(content, filename, mimeType)}
            className="gap-2"
          >
            <Download className="h-4 w-4" />
            Download
          </Button>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-auto">
        <DialogHeader>
          <DialogTitle className="font-terminal text-glow">Export Analysis Results</DialogTitle>
          <DialogDescription>
            Export your CTI analysis in multiple formats with enhanced TTP and detection context
          </DialogDescription>
          
          {/* Analysis Summary */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 p-4 bg-muted/30 rounded-lg mt-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.totalIOCs}</div>
              <div className="text-xs text-muted-foreground">IOCs</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.totalTTPs}</div>
              <div className="text-xs text-muted-foreground">TTPs</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.totalDetections}</div>
              <div className="text-xs text-muted-foreground">Detections</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.totalQueries}</div>
              <div className="text-xs text-muted-foreground">Queries</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.hasAIAnalysis ? '✓' : '✗'}</div>
              <div className="text-xs text-muted-foreground">AI Analysis</div>
            </div>
          </div>
        </DialogHeader>

        <Tabs defaultValue="cql" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="cql">CQL Bundle</TabsTrigger>
            <TabsTrigger value="csv">Enhanced CSV</TabsTrigger>
            <TabsTrigger value="stix">STIX 2.1</TabsTrigger>
            <TabsTrigger value="json">Complete JSON</TabsTrigger>
          </TabsList>

          <TabsContent value="cql" className="mt-6">
            <ExportCard
              title="CQL Query Bundle"
              description="Vendor-aware CQL queries with metadata and validation status"
              content={cqlContent}
              filename="cql-queries.cql"
              mimeType="text/plain"
              stats={[
                { label: 'Queries', value: stats.totalQueries.toString() },
                { label: 'Vendor', value: queries[0]?.vendor || 'Mixed' },
                { label: 'Module', value: queries[0]?.module || 'Mixed' }
              ]}
            />
          </TabsContent>

          <TabsContent value="csv" className="mt-6">
            <ExportCard
              title="Enhanced CSV with TTPs"
              description="IOCs enriched with MITRE ATT&CK techniques, tactics, and detection context"
              content={csvContent}
              filename="enriched-iocs.csv"
              mimeType="text/csv"
              stats={[
                { label: 'IOCs', value: stats.totalIOCs.toString() },
                { label: 'TTPs', value: stats.totalTTPs.toString() },
                { label: 'Enriched', value: stats.hasAIAnalysis ? 'Yes' : 'No' }
              ]}
            />
          </TabsContent>

          <TabsContent value="stix" className="mt-6">
            <ExportCard
              title="STIX 2.1 Bundle"
              description="Standards-compliant STIX bundle with indicators, attack patterns, and relationships"
              content={stixContent}
              filename="threat-intelligence.json"
              mimeType="application/json"
              stats={[
                { label: 'Objects', value: (JSON.parse(stixContent).objects?.length || 0).toString() },
                { label: 'Indicators', value: stats.totalIOCs.toString() },
                { label: 'Attack Patterns', value: stats.totalTTPs.toString() }
              ]}
            />
          </TabsContent>

          <TabsContent value="json" className="mt-6">
            <ExportCard
              title="Complete Analysis JSON"
              description="Full analysis results including IOCs, TTPs, detections, entities, and metadata"
              content={jsonContent}
              filename="complete-analysis.json"
              mimeType="application/json"
              stats={[
                { label: 'Total Objects', value: (stats.totalIOCs + stats.totalTTPs + stats.totalDetections + stats.totalQueries).toString() },
                { label: 'Format Version', value: '2.0' },
                { label: 'AI Enhanced', value: stats.hasAIAnalysis ? 'Yes' : 'No' }
              ]}
            />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};