import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { 
  Search, 
  Code, 
  Target, 
  Download, 
  Zap, 
  Shield, 
  FileText,
  AlertCircle,
  CheckCircle,
  Info
} from 'lucide-react';

interface HelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const HelpDialog = ({ open, onOpenChange }: HelpDialogProps) => {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Info className="h-5 w-5" />
            CQLForge Documentation
          </DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="quick-start" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="quick-start">Quick Start</TabsTrigger>
            <TabsTrigger value="features">Features</TabsTrigger>
            <TabsTrigger value="troubleshooting">Troubleshooting</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
          </TabsList>

          <TabsContent value="quick-start" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Getting Started
                </CardTitle>
                <CardDescription>
                  Transform threat intelligence into actionable CQL queries in 4 steps
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4">
                  <div className="flex gap-4">
                    <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold">
                      1
                    </div>
                    <div className="flex-1">
                      <h4 className="font-semibold flex items-center gap-2">
                        <Search className="h-4 w-4" />
                        Extract IOCs
                      </h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Paste threat reports, paste IOCs, or upload PDF files. The system automatically extracts:
                      </p>
                      <div className="mt-2 flex flex-wrap gap-1">
                        <Badge variant="outline">IP Addresses</Badge>
                        <Badge variant="outline">Domains</Badge>
                        <Badge variant="outline">URLs</Badge>
                        <Badge variant="outline">File Hashes</Badge>
                        <Badge variant="outline">Email Addresses</Badge>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold">
                      2
                    </div>
                    <div className="flex-1">
                      <h4 className="font-semibold flex items-center gap-2">
                        <Code className="h-4 w-4" />
                        Generate CQL Queries
                      </h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Select your SIEM vendor and automatically generate optimized CQL queries with proper field mappings.
                      </p>
                      <div className="mt-2 flex flex-wrap gap-1">
                        <Badge variant="outline">CrowdStrike</Badge>
                        <Badge variant="outline">Splunk</Badge>
                        <Badge variant="outline">QRadar</Badge>
                        <Badge variant="outline">Sentinel</Badge>
                        <Badge variant="outline">Elastic</Badge>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold">
                      3
                    </div>
                    <div className="flex-1">
                      <h4 className="font-semibold flex items-center gap-2">
                        <Target className="h-4 w-4" />
                        Apply Hunt Templates
                      </h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Use AI-powered hunt suggestions based on MITRE ATT&CK framework to create targeted detection rules.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold">
                      4
                    </div>
                    <div className="flex-1">
                      <h4 className="font-semibold flex items-center gap-2">
                        <Download className="h-4 w-4" />
                        Export Results
                      </h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Export your analysis in multiple formats for integration with your security workflow.
                      </p>
                      <div className="mt-2 flex flex-wrap gap-1">
                        <Badge variant="outline">CQL Queries</Badge>
                        <Badge variant="outline">CSV Reports</Badge>
                        <Badge variant="outline">STIX 2.1</Badge>
                        <Badge variant="outline">JSON</Badge>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="features" className="space-y-4">
            <div className="grid gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>IOC Extraction Engine</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Multi-format Support</p>
                      <p className="text-sm text-muted-foreground">Extract IOCs from text, PDFs, and structured reports</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">AI-Powered Analysis</p>
                      <p className="text-sm text-muted-foreground">Automatic TTP extraction and MITRE ATT&CK mapping</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Real-time Validation</p>
                      <p className="text-sm text-muted-foreground">Validate IOCs and filter out false positives</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>CQL Generation</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Vendor-Aware Mapping</p>
                      <p className="text-sm text-muted-foreground">Automatic field mapping for different SIEM platforms</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Template Library</p>
                      <p className="text-sm text-muted-foreground">25+ pre-built query templates for common scenarios</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Performance Optimization</p>
                      <p className="text-sm text-muted-foreground">Queries optimized for large-scale environments</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Hunt Suggestions</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">MITRE ATT&CK Integration</p>
                      <p className="text-sm text-muted-foreground">Hunt templates mapped to tactics and techniques</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Contextualized Recommendations</p>
                      <p className="text-sm text-muted-foreground">Suggestions based on your specific IOCs and TTPs</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="troubleshooting" className="space-y-4">
            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertCircle className="h-5 w-5 text-warning" />
                    Common Issues
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <p className="font-medium">IOCs not being extracted</p>
                    <ul className="text-sm text-muted-foreground space-y-1 ml-4">
                      <li>• Ensure text contains valid IOC formats (IPs, domains, hashes, etc.)</li>
                      <li>• Check that auto-detection is enabled in settings</li>
                      <li>• Try pasting smaller chunks of text if the input is very large</li>
                    </ul>
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <p className="font-medium">CQL queries not generating</p>
                    <ul className="text-sm text-muted-foreground space-y-1 ml-4">
                      <li>• Select a vendor from the dropdown first</li>
                      <li>• Ensure you have extracted IOCs in the previous step</li>
                      <li>• Check that the selected template supports your IOC types</li>
                    </ul>
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <p className="font-medium">PDF upload not working</p>
                    <ul className="text-sm text-muted-foreground space-y-1 ml-4">
                      <li>• Ensure the PDF is text-based (not scanned images)</li>
                      <li>• Try files smaller than 10MB</li>
                      <li>• Use modern PDF formats (avoid very old or corrupted files)</li>
                    </ul>
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <p className="font-medium">AI features not available</p>
                    <ul className="text-sm text-muted-foreground space-y-1 ml-4">
                      <li>• Configure API keys in Settings → Configure API Keys</li>
                      <li>• Ensure you have a valid OpenAI, Anthropic, or other supported API key</li>
                      <li>• Check your API key usage limits and billing status</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Performance Tips</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-4 w-4 text-primary mt-1" />
                    <p className="text-sm">Process IOCs in batches of 1000 or fewer for optimal performance</p>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-4 w-4 text-primary mt-1" />
                    <p className="text-sm">Clear browser cache if experiencing slow loading times</p>
                  </div>
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-4 w-4 text-primary mt-1" />
                    <p className="text-sm">Use Chrome or Firefox for best compatibility</p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="security" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Security & Privacy
                </CardTitle>
                <CardDescription>
                  CQLForge is designed with security and privacy in mind
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Local Data Processing</p>
                      <p className="text-sm text-muted-foreground">All IOC extraction and CQL generation happens in your browser</p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">API Key Security</p>
                      <p className="text-sm text-muted-foreground">API keys are stored only in your browser's local storage</p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">No Data Retention</p>
                      <p className="text-sm text-muted-foreground">Your IOCs and queries are not stored on our servers</p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <CheckCircle className="h-5 w-5 text-primary mt-0.5" />
                    <div>
                      <p className="font-medium">Optional AI Processing</p>
                      <p className="text-sm text-muted-foreground">AI features only activated when you provide API keys</p>
                    </div>
                  </div>
                </div>

                <Separator />

                <div className="space-y-2">
                  <h4 className="font-medium">Data Handling</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• IOCs are processed locally using regex patterns</li>
                    <li>• PDF parsing happens entirely in your browser</li>
                    <li>• Only AI analysis features send data to external APIs (when configured)</li>
                    <li>• You can disable AI features and use the tool completely offline</li>
                  </ul>
                </div>

                <Separator />

                <div className="space-y-2">
                  <h4 className="font-medium">Best Practices</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Regularly clear browser data if processing sensitive IOCs</li>
                    <li>• Use API keys with minimal required permissions</li>
                    <li>• Enable anonymization in exports when sharing reports</li>
                    <li>• Set appropriate data retention periods in settings</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};