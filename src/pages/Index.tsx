import { useState, useEffect } from 'react';
import { IOCExtractor } from '@/components/IOCExtractor';
import { QueryGenerator } from '@/components/CQLGenerator';
import { Navigation } from '@/components/Navigation';
import { MobileNavigation } from '@/components/MobileNavigation';
import { ResponsiveLayout, ResponsiveGrid, ResponsiveStack } from '@/components/ResponsiveLayout';
import { TouchOptimizedButton } from '@/components/TouchOptimizedButton';
import { SettingsDialog } from '@/components/SettingsDialog';
import { ApiKeysDialog } from '@/components/ApiKeysDialog';
import { HelpDialog } from '@/components/HelpDialog';
import { ExportDialog } from '@/components/ExportDialog';
import { HuntSuggestions } from '@/components/HuntSuggestions';
import { HuntPackManager } from '@/components/HuntPackManager';
import { QueryBuilder } from '@/components/CQLBuilder';
import { RateLimitStatus } from '@/components/RateLimitStatus';
import { QueryAnalyzer } from '@/components/CQLAnalyzer';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getIOCCounts, type IOCSet } from '@/lib/ioc-extractor';
import { useErrorHandler } from '@/hooks/useErrorHandler';
import { useIsMobile, useIsTablet } from '@/hooks/useMediaQuery';
import { analytics, trackUserAction } from '@/lib/analytics';
import { Clock, Shield, Zap, Settings, HelpCircle } from 'lucide-react';
import { ThemeToggle } from '@/components/ThemeToggle';

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
  const [generatedQueries, setGeneratedQueries] = useState<string[]>([]);
  const [extractedTTPs, setExtractedTTPs] = useState<any[]>([]);
  const [extractedDetections, setExtractedDetections] = useState<any[]>([]);
  const [extractedEntities, setExtractedEntities] = useState<any>({});
  const [apiDialogOpen, setApiDialogOpen] = useState(false);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [helpDialogOpen, setHelpDialogOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);

  const isMobile = useIsMobile();
  const isTablet = useIsTablet();

  const { handleError } = useErrorHandler();

  // Phase 4: Enhanced state for TTP tracking

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

  const handleApplyQuery = (query: string, huntId: string) => {
    try {
      setGeneratedQueries(prev => [...prev, query]);
      setActiveSection('queries');
      trackUserAction('apply_hunt_pack_query', 'HuntPackManager', { huntId });
    } catch (error) {
      handleError(error, { component: 'Index', action: 'handleApplyQuery' });
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
        return <QueryGenerator iocs={iocs} onQueriesGenerated={setGeneratedQueries} />;
      case 'analyzer':
        return <QueryAnalyzer queries={generatedQueries} />;
      case 'hunts':
        return <HuntSuggestions iocs={iocs} ttps={extractedTTPs || []} onApplyHunt={handleApplyHunt} />;
      case 'hunt-packs':
        return <HuntPackManager onApplyQuery={handleApplyQuery} />;
      case 'cql-builder':
        return <QueryBuilder />;
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
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Switch between Analyst and Pip-Boy modes</span>
                  <ThemeToggle />
                </div>
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
                  <Badge variant="secondary">Multi-Vendor Support</Badge>
                  <p className="text-sm text-muted-foreground">
                    Universal SIEM field mappings and query generation
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
    <ResponsiveLayout
      className="min-h-screen bg-background"
      mobileClassName="flex flex-col"
      desktopClassName="flex"
    >
      {/* Mobile Navigation */}
      <MobileNavigation
        activeSection={activeSection}
        onSectionChange={setActiveSection}
        iocCounts={counts}
      />
      
      {/* Desktop Sidebar Navigation */}
      {!isMobile && (
        <Navigation 
          activeSection={activeSection} 
          onSectionChange={setActiveSection}
          iocCount={counts.total}
          queryCount={generatedQueries.length}
        />
      )}
      
      {/* Main Content */}
      <div className={`flex-1 flex flex-col ${isMobile ? 'pt-16' : ''}`}>
        {/* Desktop Header */}
        {!isMobile && (
          <header className="border-b border-border bg-background/95 backdrop-blur">
            <div className="flex items-center justify-between p-4">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Zap className="h-6 w-6 text-primary" />
                  <h1 className="text-xl font-bold font-terminal text-glow">IntelForge</h1>
                </div>
                
                {counts.total > 0 && (
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="font-mono">
                      {counts.total} IOCs
                    </Badge>
                    <div className="text-xs text-muted-foreground hidden md:flex items-center gap-3">
                      {counts.ipv4 > 0 && <span>IPv4: {counts.ipv4}</span>}
                      {counts.ipv6 > 0 && <span>IPv6: {counts.ipv6}</span>}
                      {counts.domains > 0 && <span>Domains: {counts.domains}</span>}
                      {counts.urls > 0 && <span>URLs: {counts.urls}</span>}
                      {counts.sha256 > 0 && <span>SHA256: {counts.sha256}</span>}
                      {counts.md5 > 0 && <span>MD5: {counts.md5}</span>}
                      {counts.emails > 0 && <span>Emails: {counts.emails}</span>}
                    </div>
                  </div>
                )}
              </div>
              
              <ResponsiveStack direction={{ mobile: 'col', desktop: 'row' }} spacing={{ mobile: 2, desktop: 2 }}>
                <RateLimitStatus />
                <TouchOptimizedButton
                  variant="ghost"
                  size="sm"
                  onClick={() => setSettingsDialogOpen(true)}
                  className="gap-2"
                >
                  <Settings className="h-4 w-4" />
                  Settings
                </TouchOptimizedButton>
                <TouchOptimizedButton
                  variant="ghost"
                  size="sm"
                  onClick={() => setHelpDialogOpen(true)}
                  className="gap-2"
                >
                  <HelpCircle className="h-4 w-4" />
                  Help
                </TouchOptimizedButton>
              </ResponsiveStack>
            </div>
          </header>
        )}

        {/* Content Area */}
        <main className={`flex-1 overflow-auto ${isMobile ? 'p-4' : 'p-6'}`}>
          <div className={`mx-auto w-full ${isMobile ? 'max-w-full' : 'max-w-7xl'}`}>
            <div className="min-w-0">
              {renderContent()}
            </div>
          </div>
        </main>
        
        {/* Dialogs */}
        <ApiKeysDialog open={apiDialogOpen} onOpenChange={setApiDialogOpen} />
        <SettingsDialog open={settingsDialogOpen} onOpenChange={setSettingsDialogOpen} />
        <HelpDialog open={helpDialogOpen} onOpenChange={setHelpDialogOpen} />
        <ExportDialog 
          open={exportDialogOpen} 
          onOpenChange={setExportDialogOpen}
          iocs={iocs}
          queries={generatedQueries}
        />
      </div>
    </ResponsiveLayout>
  );
};

export default Index;
