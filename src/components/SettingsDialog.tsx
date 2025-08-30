import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/hooks/use-toast';
import { Shield, Eye, EyeOff, Trash2, Download, Upload, AlertTriangle } from 'lucide-react';

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface SecuritySettings {
  autoSaveQueries: boolean;
  dataRetentionDays: number;
  anonymizeExports: boolean;
  enableAnalytics: boolean;
}

interface AppSettings {
  maxIOCsPerSession: number;
  defaultVendor: string;
  enableNotifications: boolean;
  enableAutoDetection: boolean;
}

const defaultSecuritySettings: SecuritySettings = {
  autoSaveQueries: false,
  dataRetentionDays: 30,
  anonymizeExports: true,
  enableAnalytics: false
};

const defaultAppSettings: AppSettings = {
  maxIOCsPerSession: 10000,
  defaultVendor: 'splunk',
  enableNotifications: true,
  enableAutoDetection: true
};

export const SettingsDialog = ({ open, onOpenChange }: SettingsDialogProps) => {
  const { toast } = useToast();
  const [securitySettings, setSecuritySettings] = useState<SecuritySettings>(defaultSecuritySettings);
  const [appSettings, setAppSettings] = useState<AppSettings>(defaultAppSettings);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    if (open) {
      // Load settings from localStorage
      const savedSecurity = localStorage.getItem('cqlforge_security_settings');
      const savedApp = localStorage.getItem('cqlforge_app_settings');
      
      if (savedSecurity) {
        setSecuritySettings({ ...defaultSecuritySettings, ...JSON.parse(savedSecurity) });
      }
      if (savedApp) {
        setAppSettings({ ...defaultAppSettings, ...JSON.parse(savedApp) });
      }
    }
  }, [open]);

  const handleSaveSettings = () => {
    localStorage.setItem('cqlforge_security_settings', JSON.stringify(securitySettings));
    localStorage.setItem('cqlforge_app_settings', JSON.stringify(appSettings));
    toast({ 
      title: 'Settings Saved', 
      description: 'Your preferences have been saved locally.' 
    });
    onOpenChange(false);
  };

  const handleResetSettings = () => {
    setSecuritySettings(defaultSecuritySettings);
    setAppSettings(defaultAppSettings);
    localStorage.removeItem('cqlforge_security_settings');
    localStorage.removeItem('cqlforge_app_settings');
    toast({ 
      title: 'Settings Reset', 
      description: 'All settings have been reset to defaults.' 
    });
  };

  const handleExportSettings = () => {
    const exportData = {
      security: securitySettings,
      app: appSettings,
      exportDate: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cqlforge-settings-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast({ title: 'Settings Exported', description: 'Settings downloaded successfully.' });
  };

  const handleImportSettings = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const importData = JSON.parse(e.target?.result as string);
        if (importData.security) setSecuritySettings({ ...defaultSecuritySettings, ...importData.security });
        if (importData.app) setAppSettings({ ...defaultAppSettings, ...importData.app });
        toast({ title: 'Settings Imported', description: 'Settings loaded successfully.' });
      } catch (error) {
        toast({ 
          title: 'Import Failed', 
          description: 'Invalid settings file format.',
          variant: 'destructive'
        });
      }
    };
    reader.readAsText(file);
  };

  const getDataUsageInfo = () => {
    const storageUsed = Object.keys(localStorage).reduce((total, key) => {
      if (key.startsWith('cqlforge_')) {
        return total + (localStorage.getItem(key)?.length || 0);
      }
      return total;
    }, 0);
    
    return Math.round(storageUsed / 1024); // KB
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Advanced Settings & Security
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* Security Settings */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Security & Privacy</h3>
              <Badge variant="secondary" className="gap-1">
                <Shield className="h-3 w-3" />
                Local Only
              </Badge>
            </div>
            
            <div className="grid gap-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="auto-save">Auto-save queries</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically save generated queries to browser storage
                  </p>
                </div>
                <Switch
                  id="auto-save"
                  checked={securitySettings.autoSaveQueries}
                  onCheckedChange={(checked) => 
                    setSecuritySettings(prev => ({ ...prev, autoSaveQueries: checked }))
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="anonymize">Anonymize exports</Label>
                  <p className="text-sm text-muted-foreground">
                    Remove sensitive metadata from exported files
                  </p>
                </div>
                <Switch
                  id="anonymize"
                  checked={securitySettings.anonymizeExports}
                  onCheckedChange={(checked) => 
                    setSecuritySettings(prev => ({ ...prev, anonymizeExports: checked }))
                  }
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="retention">Data retention (days)</Label>
                <Input
                  id="retention"
                  type="number"
                  min="1"
                  max="365"
                  value={securitySettings.dataRetentionDays}
                  onChange={(e) => 
                    setSecuritySettings(prev => ({ 
                      ...prev, 
                      dataRetentionDays: parseInt(e.target.value) || 30 
                    }))
                  }
                  className="w-32"
                />
                <p className="text-sm text-muted-foreground">
                  Automatically clear old data after this period
                </p>
              </div>
            </div>
          </div>

          <Separator />

          {/* Application Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Application Settings</h3>
            
            <div className="grid gap-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="notifications">Enable notifications</Label>
                  <p className="text-sm text-muted-foreground">
                    Show browser notifications for completed operations
                  </p>
                </div>
                <Switch
                  id="notifications"
                  checked={appSettings.enableNotifications}
                  onCheckedChange={(checked) => 
                    setAppSettings(prev => ({ ...prev, enableNotifications: checked }))
                  }
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="auto-detect">Auto-detection</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically detect IOC patterns in pasted text
                  </p>
                </div>
                <Switch
                  id="auto-detect"
                  checked={appSettings.enableAutoDetection}
                  onCheckedChange={(checked) => 
                    setAppSettings(prev => ({ ...prev, enableAutoDetection: checked }))
                  }
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="max-iocs">Max IOCs per session</Label>
                <Input
                  id="max-iocs"
                  type="number"
                  min="100"
                  max="50000"
                  step="100"
                  value={appSettings.maxIOCsPerSession}
                  onChange={(e) => 
                    setAppSettings(prev => ({ 
                      ...prev, 
                      maxIOCsPerSession: parseInt(e.target.value) || 10000 
                    }))
                  }
                  className="w-32"
                />
              </div>
            </div>
          </div>

          <Separator />

          {/* Advanced Options */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Advanced Options</h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="gap-2"
              >
                {showAdvanced ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                {showAdvanced ? 'Hide' : 'Show'}
              </Button>
            </div>

            {showAdvanced && (
              <div className="space-y-4 p-4 bg-muted/50 rounded-lg">
                <div className="flex items-center gap-2 text-warning">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="text-sm font-medium">Advanced users only</span>
                </div>

                <div className="grid gap-4">
                  <div>
                    <Label className="text-sm font-medium">Data Usage</Label>
                    <p className="text-sm text-muted-foreground mt-1">
                      Browser storage: {getDataUsageInfo()} KB used
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleExportSettings}
                      className="gap-2"
                    >
                      <Download className="h-4 w-4" />
                      Export Settings
                    </Button>
                    
                    <div className="relative">
                      <input
                        type="file"
                        accept=".json"
                        onChange={handleImportSettings}
                        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      />
                      <Button variant="outline" size="sm" className="gap-2">
                        <Upload className="h-4 w-4" />
                        Import Settings
                      </Button>
                    </div>

                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={handleResetSettings}
                      className="gap-2"
                    >
                      <Trash2 className="h-4 w-4" />
                      Reset All
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button onClick={handleSaveSettings}>
              Save Settings
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};