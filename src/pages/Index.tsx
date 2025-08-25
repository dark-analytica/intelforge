import { useState, useEffect } from 'react';
import { Navigation } from '@/components/Navigation';
import { IOCExtractor } from '@/components/IOCExtractor';
import { CQLGenerator } from '@/components/CQLGenerator';
import { ThemeToggle } from '@/components/ThemeToggle';
import ApiKeysDialog from '@/components/ApiKeysDialog';
import { SettingsDialog } from '@/components/SettingsDialog';
import { HelpDialog } from '@/components/HelpDialog';
import { ExportDialog } from '@/components/ExportDialog';
import { HuntSuggestions } from '@/components/HuntSuggestions';
import { CQLBuilder } from '@/components/CQLBuilder';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getIOCCounts, type IOCSet } from '@/lib/ioc-extractor';
import { useErrorHandler } from '@/hooks/useErrorHandler';
import { analytics, trackUserAction } from '@/lib/analytics';
import { Clock, Shield, Zap, Settings, HelpCircle } from 'lucide-react';

const Index = () => {
  const [activeSection, setActiveSection] = useState('ingest');
  const [iocs, setIOCs] = useState<IOCSet>({
    ipv4: [],
    ipv6: [],
    domains: [],
    urls: [],
    sha256: [],
    md5: [],
    emails: []
  });
  const [apiDialogOpen, setApiDialogOpen] = useState(false);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [helpDialogOpen, setHelpDialogOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [generatedQueries, setGeneratedQueries] = useState<any[]>([]);
  
  const { handleError } = useErrorHandler();
  
  // Phase 4: Enhanced state for TTP tracking
  const [extractedTTPs, setExtractedTTPs] = useState<any[]>([]);
  const [extractedDetections, setExtractedDetections] = useState<any[]>([]);
  const [extractedEntities, setExtractedEntities] = useState<any>(null);

  const counts = getIOCCounts(iocs);

  const handleApplyHunt = (template: string, huntId: string) => {
    try {
      setGeneratedQueries(prev => [...prev, template]);
      setActiveSection('queries');
      trackUserAction('apply_hunt', 'HuntSuggestions', { huntId });
    } catch (error) {
      handleError(error, { component: 'Index', action: 'handleApplyHunt' });
    }
  };

  const renderContent = () => {
    switch (activeSection) {
      case 'ingest':
        return <IOCExtractor 
          iocs={iocs} 
          onIOCsExtracted={setIOCs} 
          onTTPsExtracted={(ttps, detections, entities) => {
            setExtractedTTPs(ttps);
            setExtractedDetections(detections);
            setExtractedEntities(entities);
          }}
        />;
      case 'queries':
        return <CQLGenerator iocs={iocs} onQueriesGenerated={setGeneratedQueries} />;
      case 'hunts':
        return <HuntSuggestions iocs={iocs} ttps={extractedTTPs || []} onApplyHunt={handleApplyHunt} />;
      case 'cql-builder':
        return <CQLBuilder />;
      case 'exports':
        return (
          <Card>
            <CardHeader>
              <CardTitle className="font-terminal text-glow">Export Options</CardTitle>
              <CardDescription>
                Export IOCs and queries in various formats
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Button 
                  variant="outline" 
                  className="gap-2"
                  onClick={() => setExportDialogOpen(true)}
                  disabled={counts.total === 0}
                >
                  <Zap className="h-4 w-4" />
                  Export CQL
                </Button>
                <Button 
                  variant="outline" 
                  className="gap-2"
                  onClick={() => setExportDialogOpen(true)}
                  disabled={counts.total === 0}
                >
                  <Zap className="h-4 w-4" />
                  Export CSV
                </Button>
                <Button 
                  variant="outline" 
                  className="gap-2"
                  onClick={() => setExportDialogOpen(true)}
                  disabled={counts.total === 0}
                >
                  <Zap className="h-4 w-4" />
                  Export STIX 2.1
                </Button>
                <Button 
                  variant="outline" 
                  className="gap-2"
                  onClick={() => setExportDialogOpen(true)}
                  disabled={counts.total === 0}
                >
                  <Zap className="h-4 w-4" />
                  Export JSON
                </Button>
              </div>
              {counts.total === 0 ? (
                <div className="text-center text-muted-foreground text-sm">
                  Extract IOCs first to enable exports
                </div>
              ) : (
                <div className="text-center text-sm">
                  <Badge variant="outline">{counts.total} IOCs ready for export</Badge>
                </div>
              )}
            </CardContent>
          </Card>
        );
      case 'settings':
        return (
          <Card>
            <CardHeader>
              <CardTitle className="font-terminal text-glow">Settings</CardTitle>
              <CardDescription>
                Configure LLM providers and application preferences
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <h3 className="text-sm font-medium mb-3">Theme</h3>
                <ThemeToggle />
              </div>
              
              <div>
                <h3 className="text-sm font-medium mb-3">LLM Providers (Optional)</h3>
                <div className="space-y-2 text-sm text-muted-foreground">
                  <p>• OpenAI/Azure OpenAI</p>
                  <p>• Anthropic Claude</p>
                  <p>• Google Gemini</p>
                  <p>• OpenRouter</p>
                </div>
                <Button variant="outline" className="mt-3" onClick={() => setApiDialogOpen(true)}>
                  Configure API Keys
                </Button>
              </div>

              <div>
                <h3 className="text-sm font-medium mb-3">Application Settings</h3>
                <div className="space-y-3">
                  <Button variant="outline" className="gap-2" onClick={() => setSettingsDialogOpen(true)}>
                    <Settings className="h-4 w-4" />
                    Advanced Settings
                  </Button>
                  <Button variant="outline" className="gap-2" onClick={() => setHelpDialogOpen(true)}>
                    <HelpCircle className="h-4 w-4" />
                    Documentation
                  </Button>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium mb-3">Data Profiles</h3>
                <div className="space-y-2">
                  <Badge variant="secondary">Default CrowdStrike</Badge>
                  <p className="text-sm text-muted-foreground">
                    Standard NG-SIEM field mappings
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        );
      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-background flex">
      {/* Sidebar Navigation */}
      <Navigation 
        activeSection={activeSection}
        onSectionChange={setActiveSection}
        iocCount={counts.total}
        queryCount={generatedQueries.length}
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Top Bar */}
        <header className="bg-card border-b border-border p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div>
                <h2 className="font-terminal text-xl text-glow">
                  {activeSection === 'ingest' && 'IOC Extraction'}
                  {activeSection === 'queries' && 'CQL Generation'}
                  {activeSection === 'hunts' && 'Hunt Ideas'}
                  {activeSection === 'cql-builder' && 'CQL Builder'}
                  {activeSection === 'exports' && 'Export Data'}
                  {activeSection === 'settings' && 'Settings'}
                </h2>
                <p className="text-sm text-muted-foreground">
                  CrowdStrike NG-SIEM Query Language Generator
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Clock className="h-4 w-4" />
                <span>Last 24h</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setHelpDialogOpen(true)}
                className="gap-2"
              >
                <HelpCircle className="h-4 w-4" />
                Help
              </Button>
              <ThemeToggle />
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 p-6 overflow-auto">
          <div className="max-w-6xl mx-auto">
            {renderContent()}
          </div>
        </main>
        <ApiKeysDialog open={apiDialogOpen} onOpenChange={setApiDialogOpen} />
        <SettingsDialog open={settingsDialogOpen} onOpenChange={setSettingsDialogOpen} />
        <HelpDialog open={helpDialogOpen} onOpenChange={setHelpDialogOpen} />
        <ExportDialog 
          open={exportDialogOpen} 
          onOpenChange={setExportDialogOpen} 
          iocs={iocs} 
          queries={generatedQueries}
          ttps={extractedTTPs}
          detections={extractedDetections}
          entities={extractedEntities}
        />
      </div>
    </div>
  );
};

export default Index;
