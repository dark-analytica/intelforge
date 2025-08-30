import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Save, 
  Upload, 
  Download, 
  Copy, 
  Trash2, 
  Plus, 
  Settings, 
  CheckCircle2, 
  AlertCircle,
  Info
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { vendors, getVendorById, getModuleById, type VendorModule } from '@/lib/vendors';

interface CustomFieldMapping {
  id: string;
  name: string;
  description: string;
  vendorId: string;
  baseModuleId?: string;
  fields: Record<string, string>;
  repos: Record<string, string>;
  validation: {
    required_fields: string[];
    notes: string[];
  };
  isCustom: true;
  createdAt: Date;
  updatedAt: Date;
}

interface FieldMappingEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSave: (mapping: CustomFieldMapping) => void;
  editingMapping?: CustomFieldMapping;
}

const defaultFields = {
  DST_IP_FIELD: 'Destination IP field name',
  SRC_IP_FIELD: 'Source IP field name',
  DOMAIN_FIELD: 'Domain/DNS field name',
  URL_FIELD: 'URL field name',
  HOST_FIELD: 'Hostname field name',
  USERNAME_FIELD: 'Username field name',
  PROC_PATH_FIELD: 'Process path field name',
  SHA256_FIELD: 'SHA256 hash field name',
  MD5_FIELD: 'MD5 hash field name',
  EMAIL_FIELD: 'Email address field name',
  ACTION_FIELD: 'Action/event type field name'
};

const defaultRepos = {
  PROXY_REPO: 'Proxy/web traffic data source',
  DNS_REPO: 'DNS query data source',
  EDR_REPO: 'Endpoint detection data source',
  IDP_REPO: 'Identity/authentication data source',
  EMAIL_REPO: 'Email security data source'
};

export const FieldMappingEditor: React.FC<FieldMappingEditorProps> = ({
  open,
  onOpenChange,
  onSave,
  editingMapping
}) => {
  const [mapping, setMapping] = useState<Partial<CustomFieldMapping>>({
    name: '',
    description: '',
    vendorId: '',
    baseModuleId: '',
    fields: { ...Object.fromEntries(Object.keys(defaultFields).map(key => [key, ''])) },
    repos: { ...Object.fromEntries(Object.keys(defaultRepos).map(key => [key, ''])) },
    validation: {
      required_fields: [],
      notes: []
    }
  });
  
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [importData, setImportData] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    if (editingMapping) {
      setMapping(editingMapping);
    } else {
      resetForm();
    }
  }, [editingMapping, open]);

  const resetForm = () => {
    setMapping({
      name: '',
      description: '',
      vendorId: '',
      baseModuleId: '',
      fields: { ...Object.fromEntries(Object.keys(defaultFields).map(key => [key, ''])) },
      repos: { ...Object.fromEntries(Object.keys(defaultRepos).map(key => [key, ''])) },
      validation: {
        required_fields: [],
        notes: []
      }
    });
    setValidationErrors([]);
    setImportData('');
  };

  const handleVendorChange = (vendorId: string) => {
    setMapping(prev => ({ ...prev, vendorId, baseModuleId: '' }));
  };

  const handleBaseModuleChange = (moduleId: string) => {
    const module = getModuleById(mapping.vendorId!, moduleId);
    if (module) {
      setMapping(prev => ({
        ...prev,
        baseModuleId: moduleId,
        fields: { ...module.fields },
        repos: { ...module.repos },
        validation: {
          required_fields: module.validation?.required_fields || [],
          notes: module.validation?.notes || []
        }
      }));
    }
  };

  const handleFieldChange = (fieldKey: string, value: string) => {
    setMapping(prev => ({
      ...prev,
      fields: { ...prev.fields, [fieldKey]: value }
    }));
  };

  const handleRepoChange = (repoKey: string, value: string) => {
    setMapping(prev => ({
      ...prev,
      repos: { ...prev.repos, [repoKey]: value }
    }));
  };

  const addCustomField = () => {
    const fieldName = prompt('Enter field name (e.g., CUSTOM_FIELD):');
    if (fieldName && !mapping.fields![fieldName]) {
      setMapping(prev => ({
        ...prev,
        fields: { ...prev.fields, [fieldName]: '' }
      }));
    }
  };

  const removeCustomField = (fieldKey: string) => {
    if (!defaultFields[fieldKey as keyof typeof defaultFields]) {
      const newFields = { ...mapping.fields };
      delete newFields[fieldKey];
      setMapping(prev => ({ ...prev, fields: newFields }));
    }
  };

  const validateMapping = (): boolean => {
    const errors: string[] = [];
    
    if (!mapping.name?.trim()) {
      errors.push('Mapping name is required');
    }
    
    if (!mapping.vendorId) {
      errors.push('Vendor selection is required');
    }
    
    if (!mapping.description?.trim()) {
      errors.push('Description is required');
    }
    
    // Check for empty required fields
    const emptyFields = Object.entries(mapping.fields || {})
      .filter(([key, value]) => defaultFields[key as keyof typeof defaultFields] && !value.trim())
      .map(([key]) => key);
    
    if (emptyFields.length > 0) {
      errors.push(`Required fields are empty: ${emptyFields.join(', ')}`);
    }
    
    // Check for empty required repos
    const emptyRepos = Object.entries(mapping.repos || {})
      .filter(([key, value]) => defaultRepos[key as keyof typeof defaultRepos] && !value.trim())
      .map(([key]) => key);
    
    if (emptyRepos.length > 0) {
      errors.push(`Required data sources are empty: ${emptyRepos.join(', ')}`);
    }
    
    setValidationErrors(errors);
    return errors.length === 0;
  };

  const handleSave = () => {
    if (!validateMapping()) {
      return;
    }
    
    const customMapping: CustomFieldMapping = {
      id: editingMapping?.id || `custom-${Date.now()}`,
      name: mapping.name!,
      description: mapping.description!,
      vendorId: mapping.vendorId!,
      baseModuleId: mapping.baseModuleId,
      fields: mapping.fields!,
      repos: mapping.repos!,
      validation: mapping.validation!,
      isCustom: true,
      createdAt: editingMapping?.createdAt || new Date(),
      updatedAt: new Date()
    };
    
    onSave(customMapping);
    toast({
      title: "Field mapping saved",
      description: `Custom mapping "${customMapping.name}" has been saved successfully.`
    });
    onOpenChange(false);
  };

  const handleImport = () => {
    try {
      const imported = JSON.parse(importData);
      if (imported.fields && imported.repos) {
        setMapping(prev => ({
          ...prev,
          ...imported,
          id: undefined // Generate new ID
        }));
        toast({
          title: "Configuration imported",
          description: "Field mapping configuration has been imported successfully."
        });
      } else {
        throw new Error('Invalid format');
      }
    } catch (error) {
      toast({
        title: "Import failed",
        description: "Invalid JSON format or missing required fields.",
        variant: "destructive"
      });
    }
  };

  const handleExport = () => {
    const exportData = {
      name: mapping.name,
      description: mapping.description,
      vendorId: mapping.vendorId,
      fields: mapping.fields,
      repos: mapping.repos,
      validation: mapping.validation
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${mapping.name || 'field-mapping'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectedVendor = mapping.vendorId ? getVendorById(mapping.vendorId) : null;
  const availableModules = selectedVendor?.modules || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            {editingMapping ? 'Edit Field Mapping' : 'Create Custom Field Mapping'}
          </DialogTitle>
          <DialogDescription>
            Create or modify field mappings for your SIEM platform. This allows you to customize how IOCs are mapped to your specific field names.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-[70vh] pr-4">
          <Tabs defaultValue="basic" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="basic">Basic Info</TabsTrigger>
              <TabsTrigger value="fields">Field Mappings</TabsTrigger>
              <TabsTrigger value="repos">Data Sources</TabsTrigger>
              <TabsTrigger value="advanced">Advanced</TabsTrigger>
            </TabsList>

            <TabsContent value="basic" className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Mapping Name *</Label>
                  <Input
                    id="name"
                    value={mapping.name || ''}
                    onChange={(e) => setMapping(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="e.g., My Custom Splunk Mapping"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="vendor">Target Vendor *</Label>
                  <Select value={mapping.vendorId || ''} onValueChange={handleVendorChange}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select vendor" />
                    </SelectTrigger>
                    <SelectContent>
                      {vendors.map(vendor => (
                        <SelectItem key={vendor.id} value={vendor.id}>
                          {vendor.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description *</Label>
                <Textarea
                  id="description"
                  value={mapping.description || ''}
                  onChange={(e) => setMapping(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Describe this field mapping configuration..."
                  rows={3}
                />
              </div>

              {selectedVendor && availableModules.length > 0 && (
                <div className="space-y-2">
                  <Label htmlFor="baseModule">Base Template (Optional)</Label>
                  <Select value={mapping.baseModuleId || ''} onValueChange={handleBaseModuleChange}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select base template to copy from" />
                    </SelectTrigger>
                    <SelectContent>
                      {availableModules.map(module => (
                        <SelectItem key={module.id} value={module.id}>
                          {module.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              {validationErrors.length > 0 && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    <ul className="list-disc list-inside">
                      {validationErrors.map((error, index) => (
                        <li key={index}>{error}</li>
                      ))}
                    </ul>
                  </AlertDescription>
                </Alert>
              )}
            </TabsContent>

            <TabsContent value="fields" className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium">Field Mappings</h3>
                <Button variant="outline" size="sm" onClick={addCustomField}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Custom Field
                </Button>
              </div>

              <div className="grid gap-4">
                {Object.entries(mapping.fields || {}).map(([fieldKey, fieldValue]) => (
                  <Card key={fieldKey}>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <CardTitle className="text-sm">{fieldKey}</CardTitle>
                          <CardDescription className="text-xs">
                            {defaultFields[fieldKey as keyof typeof defaultFields] || 'Custom field'}
                          </CardDescription>
                        </div>
                        {!defaultFields[fieldKey as keyof typeof defaultFields] && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeCustomField(fieldKey)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent>
                      <Input
                        value={fieldValue}
                        onChange={(e) => handleFieldChange(fieldKey, e.target.value)}
                        placeholder={`Enter ${fieldKey.toLowerCase()} field name`}
                      />
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="repos" className="space-y-4">
              <h3 className="text-lg font-medium">Data Source Mappings</h3>
              
              <div className="grid gap-4">
                {Object.entries(mapping.repos || {}).map(([repoKey, repoValue]) => (
                  <Card key={repoKey}>
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">{repoKey}</CardTitle>
                      <CardDescription className="text-xs">
                        {defaultRepos[repoKey as keyof typeof defaultRepos]}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Input
                        value={repoValue}
                        onChange={(e) => handleRepoChange(repoKey, e.target.value)}
                        placeholder={`Enter ${repoKey.toLowerCase()} data source`}
                      />
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="advanced" className="space-y-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-medium">Advanced Configuration</h3>
                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={showAdvanced}
                      onCheckedChange={setShowAdvanced}
                    />
                    <Label>Show advanced options</Label>
                  </div>
                </div>

                {showAdvanced && (
                  <>
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Validation Rules</CardTitle>
                        <CardDescription>Configure validation requirements for this mapping</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        <div>
                          <Label>Required Fields (comma-separated)</Label>
                          <Input
                            value={mapping.validation?.required_fields?.join(', ') || ''}
                            onChange={(e) => setMapping(prev => ({
                              ...prev,
                              validation: {
                                ...prev.validation!,
                                required_fields: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                              }
                            }))}
                            placeholder="timestamp, hostname"
                          />
                        </div>
                        
                        <div>
                          <Label>Validation Notes</Label>
                          <Textarea
                            value={mapping.validation?.notes?.join('\n') || ''}
                            onChange={(e) => setMapping(prev => ({
                              ...prev,
                              validation: {
                                ...prev.validation!,
                                notes: e.target.value.split('\n').filter(Boolean)
                              }
                            }))}
                            placeholder="Enter validation notes, one per line"
                            rows={3}
                          />
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Import/Export</CardTitle>
                        <CardDescription>Import or export field mapping configurations</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        <div className="flex gap-2">
                          <Button variant="outline" onClick={handleExport} disabled={!mapping.name}>
                            <Download className="h-4 w-4 mr-2" />
                            Export
                          </Button>
                          <Button variant="outline" onClick={handleImport} disabled={!importData.trim()}>
                            <Upload className="h-4 w-4 mr-2" />
                            Import
                          </Button>
                        </div>
                        
                        <div>
                          <Label>Import JSON Configuration</Label>
                          <Textarea
                            value={importData}
                            onChange={(e) => setImportData(e.target.value)}
                            placeholder="Paste JSON configuration here..."
                            rows={4}
                          />
                        </div>
                      </CardContent>
                    </Card>
                  </>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </ScrollArea>

        <Separator />

        <div className="flex justify-between">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" onClick={resetForm}>
              Reset
            </Button>
            <Button onClick={handleSave}>
              <Save className="h-4 w-4 mr-2" />
              Save Mapping
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
