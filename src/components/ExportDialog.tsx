import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Download, Copy, CheckCircle } from 'lucide-react';
import { IOCSet } from '@/lib/ioc-extractor';
import { exportToCQL, exportToCSV, exportToSTIX, exportToJSON, downloadFile, ExportData } from '@/lib/exporters';
import { useToast } from '@/hooks/use-toast';

interface ExportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  iocs: IOCSet;
  queries: string[];
}

export const ExportDialog = ({ open, onOpenChange, iocs, queries }: ExportDialogProps) => {
  const [copied, setCopied] = useState<string | null>(null);
  const { toast } = useToast();

  const exportData: ExportData = {
    meta: {
      source_title: 'CQLForge Analysis',
      tlp: 'AMBER',
      generated_at: new Date().toISOString()
    },
    iocs,
    ttps: [], // Would be populated by LLM if enabled
    profile: 'default',
    queries: { cql: queries }
  };

  const handleCopy = async (content: string, type: string) => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(type);
      setTimeout(() => setCopied(null), 2000);
      toast({
        title: "Copied to clipboard",
        description: `${type} data copied successfully`
      });
    } catch (error) {
      toast({
        title: "Copy failed",
        description: "Failed to copy to clipboard",
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

  const cqlContent = exportToCQL(queries);
  const csvContent = exportToCSV(iocs);
  const stixContent = exportToSTIX(iocs, exportData.meta);
  const jsonContent = exportToJSON(exportData);

  const ExportCard = ({ 
    title, 
    description, 
    content, 
    filename, 
    mimeType, 
    type 
  }: { 
    title: string; 
    description: string; 
    content: string; 
    filename: string; 
    mimeType: string; 
    type: string; 
  }) => (
    <div className="space-y-4">
      <div>
        <h3 className="font-semibold text-sm">{title}</h3>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      
      <div className="bg-muted/50 border rounded-lg p-3">
        <pre className="text-xs font-mono overflow-auto max-h-32 whitespace-pre-wrap">
          {content.slice(0, 200)}
          {content.length > 200 && '...'}
        </pre>
      </div>
      
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => handleCopy(content, type)}
          className="gap-2 flex-1"
        >
          {copied === type ? <CheckCircle className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          {copied === type ? 'Copied!' : 'Copy'}
        </Button>
        
        <Button
          variant="outline"
          size="sm"
          onClick={() => handleDownload(content, filename, mimeType)}
          className="gap-2 flex-1"
        >
          <Download className="h-4 w-4" />
          Download
        </Button>
      </div>
    </div>
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-auto">
        <DialogHeader>
          <DialogTitle className="font-terminal text-glow">Export Analysis</DialogTitle>
          <DialogDescription>
            Export your IOCs and queries in various formats
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="flex gap-2">
            <Badge variant="outline">{Object.values(iocs).flat().length} IOCs</Badge>
            <Badge variant="outline">{queries.length} Queries</Badge>
          </div>

          <Tabs defaultValue="cql" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="cql">CQL</TabsTrigger>
              <TabsTrigger value="csv">CSV</TabsTrigger>
              <TabsTrigger value="stix">STIX 2.1</TabsTrigger>
              <TabsTrigger value="json">JSON</TabsTrigger>
            </TabsList>

            <TabsContent value="cql" className="mt-4">
              <ExportCard
                title="CrowdStrike Query Language"
                description="Ready-to-use CQL queries for NG-SIEM"
                content={cqlContent}
                filename="cqlforge-queries.cql"
                mimeType="text/plain"
                type="CQL"
              />
            </TabsContent>

            <TabsContent value="csv" className="mt-4">
              <ExportCard
                title="IOC CSV Export"
                description="Indicators of Compromise in CSV format"
                content={csvContent}
                filename="cqlforge-iocs.csv"
                mimeType="text/csv"
                type="CSV"
              />
            </TabsContent>

            <TabsContent value="stix" className="mt-4">
              <ExportCard
                title="STIX 2.1 Bundle"
                description="Structured Threat Information eXchange format"
                content={stixContent}
                filename="cqlforge-stix.json"
                mimeType="application/json"
                type="STIX"
              />
            </TabsContent>

            <TabsContent value="json" className="mt-4">
              <ExportCard
                title="Full Analysis JSON"
                description="Complete analysis data in structured format"
                content={jsonContent}
                filename="cqlforge-analysis.json"
                mimeType="application/json"
                type="JSON"
              />
            </TabsContent>
          </Tabs>
        </div>
      </DialogContent>
    </Dialog>
  );
};