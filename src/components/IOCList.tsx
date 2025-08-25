import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { ChevronDown, ChevronUp, Copy, X, Plus, Search } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { type IOCSet } from '@/lib/ioc-extractor';

interface IOCListProps {
  iocs: IOCSet;
  onIOCsUpdated: (iocs: IOCSet) => void;
}

export const IOCList = ({ iocs, onIOCsUpdated }: IOCListProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [newIOC, setNewIOC] = useState<Record<keyof IOCSet, string>>({
    ipv4: '', ipv6: '', domains: '', urls: '', sha256: '', md5: '', emails: ''
  });
  const { toast } = useToast();

  const iocTypes: Array<{ key: keyof IOCSet; label: string; icon: string }> = [
    { key: 'ipv4', label: 'IPv4 Addresses', icon: '🌐' },
    { key: 'ipv6', label: 'IPv6 Addresses', icon: '🌐' },
    { key: 'domains', label: 'Domains', icon: '🔗' },
    { key: 'urls', label: 'URLs', icon: '🌍' },
    { key: 'sha256', label: 'SHA256 Hashes', icon: '🔐' },
    { key: 'md5', label: 'MD5 Hashes', icon: '🔐' },
    { key: 'emails', label: 'Email Addresses', icon: '📧' }
  ];

  const totalIOCs = Object.values(iocs).reduce((sum, arr) => sum + arr.length, 0);

  const copyIOC = async (ioc: string) => {
    await navigator.clipboard.writeText(ioc);
    toast({ title: 'Copied', description: `${ioc} copied to clipboard` });
  };

  const copyAllIOCs = async (type: keyof IOCSet) => {
    const allIOCs = iocs[type].join('\n');
    await navigator.clipboard.writeText(allIOCs);
    toast({ 
      title: 'Copied All', 
      description: `All ${iocs[type].length} ${type} IOCs copied to clipboard` 
    });
  };

  const removeIOC = (type: keyof IOCSet, index: number) => {
    const updated = { ...iocs };
    updated[type] = updated[type].filter((_, i) => i !== index);
    onIOCsUpdated(updated);
    toast({ title: 'Removed', description: 'IOC removed from list' });
  };

  const addIOC = (type: keyof IOCSet) => {
    const value = newIOC[type].trim();
    if (!value) return;

    const updated = { ...iocs };
    if (!updated[type].includes(value)) {
      updated[type] = [...updated[type], value];
      onIOCsUpdated(updated);
      setNewIOC(prev => ({ ...prev, [type]: '' }));
      toast({ title: 'Added', description: `IOC added to ${type} list` });
    } else {
      toast({ title: 'Duplicate', description: 'IOC already exists in list', variant: 'destructive' });
    }
  };

  const filterIOCs = (iocList: string[]) => {
    if (!searchTerm) return iocList;
    return iocList.filter(ioc => 
      ioc.toLowerCase().includes(searchTerm.toLowerCase())
    );
  };

  if (totalIOCs === 0) {
    return null;
  }

  return (
    <Card>
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <CollapsibleTrigger asChild>
          <CardHeader className="cursor-pointer hover:bg-muted/50 transition-colors">
            <div className="flex items-center justify-between">
              <CardTitle className="font-terminal text-glow flex items-center gap-2">
                📋 Extracted IOCs ({totalIOCs})
                {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </CardTitle>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        
        <CollapsibleContent>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search IOCs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="flex-1"
                />
              </div>

              <Tabs defaultValue="ipv4" className="w-full">
                <TabsList className="grid grid-cols-4 lg:grid-cols-7 w-full">
                  {iocTypes.map(({ key, label, icon }) => (
                    <TabsTrigger key={key} value={key} className="text-xs">
                      {icon} {iocs[key].length}
                    </TabsTrigger>
                  ))}
                </TabsList>

                {iocTypes.map(({ key, label }) => (
                  <TabsContent key={key} value={key} className="mt-4">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium">{label}</h4>
                        {iocs[key].length > 0 && (
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => copyAllIOCs(key)}
                            className="gap-1"
                          >
                            <Copy className="h-3 w-3" />
                            Copy All
                          </Button>
                        )}
                      </div>

                      <div className="flex gap-2">
                        <Input
                          placeholder={`Add new ${key}...`}
                          value={newIOC[key]}
                          onChange={(e) => setNewIOC(prev => ({ ...prev, [key]: e.target.value }))}
                          onKeyDown={(e) => e.key === 'Enter' && addIOC(key)}
                        />
                        <Button 
                          variant="outline" 
                          size="sm" 
                          onClick={() => addIOC(key)}
                          disabled={!newIOC[key].trim()}
                        >
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>

                      {iocs[key].length === 0 ? (
                        <div className="text-center py-8 text-muted-foreground">
                          No {label.toLowerCase()} found
                        </div>
                      ) : (
                        <div className="max-h-64 overflow-y-auto space-y-2">
                          {filterIOCs(iocs[key]).map((ioc, index) => {
                            const originalIndex = iocs[key].indexOf(ioc);
                            return (
                              <div key={`${ioc}-${originalIndex}`} className="flex items-center justify-between p-2 bg-muted/30 rounded-md group">
                                <code className="text-sm font-mono text-primary bg-background px-2 py-1 rounded flex-1">
                                  {ioc}
                                </code>
                                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyIOC(ioc)}
                                    className="h-6 w-6 p-0"
                                  >
                                    <Copy className="h-3 w-3" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => removeIOC(key, originalIndex)}
                                    className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                                  >
                                    <X className="h-3 w-3" />
                                  </Button>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {searchTerm && filterIOCs(iocs[key]).length === 0 && iocs[key].length > 0 && (
                        <div className="text-center py-4 text-muted-foreground">
                          No {label.toLowerCase()} match "{searchTerm}"
                        </div>
                      )}

                      {iocs[key].length > 0 && (
                        <div className="flex justify-between items-center text-xs text-muted-foreground pt-2 border-t">
                          <span>
                            {searchTerm 
                              ? `${filterIOCs(iocs[key]).length} of ${iocs[key].length} shown`
                              : `${iocs[key].length} total`
                            }
                          </span>
                          <Badge variant="secondary">{label}</Badge>
                        </div>
                      )}
                    </div>
                  </TabsContent>
                ))}
              </Tabs>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
};