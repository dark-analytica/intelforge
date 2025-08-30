import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetTrigger, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Badge } from '@/components/ui/badge';
import { Menu, X, Zap, Search, Target, Package, Code, FileText, BarChart3 } from 'lucide-react';
import { useIsMobile } from '@/hooks/useMediaQuery';

interface MobileNavigationProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
  iocCounts: {
    total: number;
    ipv4: number;
    ipv6: number;
    domains: number;
    urls: number;
    sha256: number;
    md5: number;
    emails: number;
  };
}

const navigationItems = [
  { id: 'ingest', label: 'IOC Ingest', icon: Search, description: 'Extract IOCs from text' },
  { id: 'queries', label: 'Query Generator', icon: Code, description: 'Generate multi-vendor queries' },
  { id: 'analyzer', label: 'Performance', icon: BarChart3, description: 'Analyze query performance' },
  { id: 'hunts', label: 'Hunt Suggestions', icon: Target, description: 'Get hunt recommendations' },
  { id: 'hunt-packs', label: 'Hunt Packs', icon: Package, description: 'Manage hunt packs' },
  { id: 'cql-builder', label: 'Query Builder', icon: Code, description: 'Build custom queries' },
  { id: 'exports', label: 'Export', icon: FileText, description: 'Export data' }
];

export const MobileNavigation: React.FC<MobileNavigationProps> = ({
  activeSection,
  onSectionChange,
  iocCounts
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const isMobile = useIsMobile();

  if (!isMobile) return null;

  const handleSectionChange = (section: string) => {
    onSectionChange(section);
    setIsOpen(false);
  };

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-background/95 backdrop-blur border-b border-border">
      <div className="flex items-center justify-between p-4">
        <div className="flex items-center gap-2">
          <Zap className="h-6 w-6 text-primary" />
          <span className="font-bold text-lg">IntelForge</span>
        </div>
        
        <div className="flex items-center gap-2">
          {iocCounts.total > 0 && (
            <Badge variant="secondary" className="text-xs">
              {iocCounts.total} IOCs
            </Badge>
          )}
          
          <Sheet open={isOpen} onOpenChange={setIsOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="sm" className="p-2">
                <Menu className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="w-80">
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5 text-primary" />
                  Navigation
                </SheetTitle>
              </SheetHeader>
              
              <div className="mt-6 space-y-2">
                {navigationItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeSection === item.id;
                  
                  return (
                    <Button
                      key={item.id}
                      variant={isActive ? "default" : "ghost"}
                      className="w-full justify-start h-auto p-3"
                      onClick={() => handleSectionChange(item.id)}
                    >
                      <div className="flex items-start gap-3 w-full">
                        <Icon className="h-4 w-4 mt-0.5 flex-shrink-0" />
                        <div className="text-left flex-1">
                          <div className="font-medium text-sm">{item.label}</div>
                          <div className="text-xs text-muted-foreground mt-0.5">
                            {item.description}
                          </div>
                        </div>
                      </div>
                    </Button>
                  );
                })}
              </div>
              
              {iocCounts.total > 0 && (
                <div className="mt-6 p-3 bg-muted rounded-lg">
                  <div className="text-sm font-medium mb-2">Current IOCs</div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {iocCounts.ipv4 > 0 && (
                      <div className="flex justify-between">
                        <span>IPv4:</span>
                        <span className="font-mono">{iocCounts.ipv4}</span>
                      </div>
                    )}
                    {iocCounts.ipv6 > 0 && (
                      <div className="flex justify-between">
                        <span>IPv6:</span>
                        <span className="font-mono">{iocCounts.ipv6}</span>
                      </div>
                    )}
                    {iocCounts.domains > 0 && (
                      <div className="flex justify-between">
                        <span>Domains:</span>
                        <span className="font-mono">{iocCounts.domains}</span>
                      </div>
                    )}
                    {iocCounts.urls > 0 && (
                      <div className="flex justify-between">
                        <span>URLs:</span>
                        <span className="font-mono">{iocCounts.urls}</span>
                      </div>
                    )}
                    {iocCounts.sha256 > 0 && (
                      <div className="flex justify-between">
                        <span>SHA256:</span>
                        <span className="font-mono">{iocCounts.sha256}</span>
                      </div>
                    )}
                    {iocCounts.md5 > 0 && (
                      <div className="flex justify-between">
                        <span>MD5:</span>
                        <span className="font-mono">{iocCounts.md5}</span>
                      </div>
                    )}
                    {iocCounts.emails > 0 && (
                      <div className="flex justify-between">
                        <span>Emails:</span>
                        <span className="font-mono">{iocCounts.emails}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </div>
  );
};
