import { useState, useEffect } from 'react';
import { Navigation } from '@/components/Navigation';
import { IOCExtractor } from '@/components/IOCExtractor';
import { CQLGenerator } from '@/components/CQLGenerator';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { getIOCCounts, type IOCSet } from '@/lib/ioc-extractor';
import { Clock, Shield, Zap } from 'lucide-react';

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

  const counts = getIOCCounts(iocs);

  const renderContent = () => {
    switch (activeSection) {
      case 'ingest':
        return <IOCExtractor iocs={iocs} onIOCsExtracted={setIOCs} />;
      case 'queries':
        return <CQLGenerator iocs={iocs} />;
      case 'hunts':
        return (
          <Card>
            <CardHeader>
              <CardTitle className="font-terminal text-glow">ATT&CK Hunt Ideas</CardTitle>
              <CardDescription>
                AI-generated hunt suggestions mapped to MITRE ATT&CK techniques
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Hunt suggestions will appear here after IOC extraction</p>
                <p className="text-sm mt-2">Requires LLM configuration in Settings</p>
              </div>
            </CardContent>
          </Card>
        );
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
                <Button variant="outline" disabled className="gap-2">
                  <Zap className="h-4 w-4" />
                  Export CQL
                </Button>
                <Button variant="outline" disabled className="gap-2">
                  <Zap className="h-4 w-4" />
                  Export CSV
                </Button>
                <Button variant="outline" disabled className="gap-2">
                  <Zap className="h-4 w-4" />
                  Export STIX 2.1
                </Button>
                <Button variant="outline" disabled className="gap-2">
                  <Zap className="h-4 w-4" />
                  Export JSON
                </Button>
              </div>
              <div className="text-center text-muted-foreground text-sm">
                Extract IOCs and generate queries to enable exports
              </div>
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
                <Button variant="outline" disabled className="mt-3">
                  Configure API Keys
                </Button>
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
        queryCount={0}
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
      </div>
    </div>
  );
};

export default Index;
