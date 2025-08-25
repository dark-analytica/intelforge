import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle, AlertTriangle, ExternalLink } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { vendors, validateFieldMapping } from '@/lib/vendors';

interface VendorPickerProps {
  selectedVendor: string;
  selectedModule: string;
  onVendorChange: (vendorId: string) => void;
  onModuleChange: (module: string) => void;
  generatedQuery?: string;
}

export const VendorPicker = ({ 
  selectedVendor, 
  selectedModule, 
  onVendorChange, 
  onModuleChange,
  generatedQuery 
}: VendorPickerProps) => {
  const selectedVendorObj = vendors.find(v => v.id === selectedVendor);
  const selectedModuleObj = selectedVendorObj?.modules.find(m => m.id === selectedModule);
  
  // Validate field mapping if we have a query
  const validation = selectedVendorObj && selectedModuleObj && generatedQuery ? 
    validateFieldMapping(selectedVendor, selectedModule, [
      'DST_IP_FIELD', 'SRC_IP_FIELD', 'DOMAIN_FIELD', 'HOST_FIELD', 'USERNAME_FIELD'
    ]) : null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="text-sm font-medium mb-2 block">Vendor</label>
          <Select value={selectedVendor} onValueChange={onVendorChange}>
            <SelectTrigger>
              <SelectValue placeholder="Select vendor..." />
            </SelectTrigger>
            <SelectContent>
              {vendors.map((vendor) => (
                <SelectItem key={vendor.id} value={vendor.id}>
                  <div className="flex flex-col">
                    <span>{vendor.name}</span>
                    <span className="text-xs text-muted-foreground">{vendor.description}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {selectedVendorObj?.documentation_url && (
            <Button
              variant="ghost"
              size="sm"
              asChild
              className="mt-2 h-6 px-2 text-xs"
            >
              <a href={selectedVendorObj.documentation_url} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-3 w-3 mr-1" />
                Documentation
              </a>
            </Button>
          )}
        </div>

        <div>
          <label className="text-sm font-medium mb-2 block">Module</label>
          <Select 
            value={selectedModule} 
            onValueChange={onModuleChange}
            disabled={!selectedVendor}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select module..." />
            </SelectTrigger>
            <SelectContent>
              {selectedVendorObj?.modules.map((module) => (
                <SelectItem key={module.id} value={module.id}>
                  <div className="flex flex-col">
                    <span>{module.name}</span>
                    <span className="text-xs text-muted-foreground">{module.description}</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {selectedModuleObj && (
        <div className="space-y-4">
          <div>
            <h4 className="font-medium mb-2">Field Mappings</h4>
            <div className="flex flex-wrap gap-2">
              {Object.entries(selectedModuleObj.fields).map(([key, value]) => (
                <Badge key={key} variant="secondary" className="text-xs">
                  {key}: {value}
                </Badge>
              ))}
            </div>
          </div>

          <div>
            <h4 className="font-medium mb-2">Repository Mappings</h4>
            <div className="flex flex-wrap gap-2">
              {Object.entries(selectedModuleObj.repos).map(([key, value]) => (
                <Badge key={key} variant="outline" className="text-xs font-mono">
                  {key}: {value}
                </Badge>
              ))}
            </div>
          </div>

          {validation && (
            <Alert variant={validation.valid ? "default" : "destructive"}>
              {validation.valid ? <CheckCircle className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
              <AlertDescription>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className={`font-medium ${validation.valid ? 'text-green-600' : 'text-red-600'}`}>
                      Field Validation: {validation.valid ? 'Passed' : 'Issues Found'}
                    </span>
                    {validation.valid && <Badge variant="secondary">All required fields available</Badge>}
                  </div>
                  
                  {validation.missing.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-red-600">Missing fields:</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {validation.missing.map((field) => (
                          <Badge key={field} variant="destructive" className="text-xs">
                            {field}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {validation.warnings.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-amber-600">Notes:</p>
                      <ul className="text-xs text-muted-foreground mt-1 space-y-1">
                        {validation.warnings.map((warning, i) => (
                          <li key={i}>• {warning}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </AlertDescription>
            </Alert>
          )}
        </div>
      )}
    </div>
  );
};