import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { 
  Search, 
  Code, 
  Target, 
  Download, 
  Settings,
  ChevronRight,
  Activity
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavigationProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
  iocCount: number;
  queryCount: number;
}

const navigationItems = [
  { id: 'ingest', label: 'IOCs', icon: Search, badge: 'iocCount' },
  { id: 'queries', label: 'Queries', icon: Code, badge: 'queryCount' },
  { id: 'hunts', label: 'Hunts', icon: Target },
  { id: 'cql-builder', label: 'CQL Builder', icon: Activity },
  { id: 'exports', label: 'Exports', icon: Download },
  { id: 'settings', label: 'Settings', icon: Settings }
];

export const Navigation = ({ 
  activeSection, 
  onSectionChange, 
  iocCount, 
  queryCount 
}: NavigationProps) => {
  const getBadgeValue = (badgeType?: string) => {
    switch (badgeType) {
      case 'iocCount': return iocCount;
      case 'queryCount': return queryCount;
      default: return 0;
    }
  };

  return (
    <div className="w-64 bg-card border-r border-border h-full flex flex-col">
      {/* Header */}
      <div className="p-6 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
            <Activity className="h-5 w-5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="font-terminal text-lg text-glow">CQLForge</h1>
            <p className="text-xs text-muted-foreground">CTI → CQL</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <div className="space-y-2">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            const badgeValue = getBadgeValue(item.badge);
            const isActive = activeSection === item.id;
            
            return (
              <Button
                key={item.id}
                variant={isActive ? "secondary" : "ghost"}
                className={cn(
                  "w-full justify-start gap-3 text-left",
                  isActive && "bg-primary/20 text-primary border border-primary/30"
                )}
                onClick={() => onSectionChange(item.id)}
              >
                <Icon className={cn(
                  "h-4 w-4",
                  isActive && "text-glow"
                )} />
                <span className="flex-1">{item.label}</span>
                {badgeValue > 0 && (
                  <span className="bg-primary/20 text-primary px-2 py-0.5 rounded-full text-xs">
                    {badgeValue}
                  </span>
                )}
                {isActive && <ChevronRight className="h-4 w-4" />}
              </Button>
            );
          })}
        </div>
      </nav>

      <Separator className="mx-4" />

      {/* Footer */}
      <div className="p-4">
        <div className="text-xs text-muted-foreground space-y-1">
          <div className="flex justify-between">
            <span>v1.0.0</span>
            <span>MIT</span>
          </div>
          <div className="text-center">
            CrowdStrike NG-SIEM
          </div>
        </div>
      </div>
    </div>
  );
};