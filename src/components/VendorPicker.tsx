import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { AlertTriangle, CheckCircle, Info } from 'lucide-react';
import { vendors, validateCPS, type Vendor } from '@/lib/vendors';

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
  const vendor = vendors.find(v => v.id === selectedVendor);
  const validation = generatedQuery && vendor ? validateCPS(generatedQuery, vendor, selectedModule) : null;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">Vendor</label>
          <Select value={selectedVendor} onValueChange={onVendorChange}>
            <SelectTrigger>
              <SelectValue placeholder="Select vendor..." />
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

        <div className="space-y-2">
          <label className="text-sm font-medium">Module</label>
          <Select 
            value={selectedModule} 
            onValueChange={onModuleChange}
            disabled={!vendor}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select module..." />
            </SelectTrigger>
            <SelectContent>
              {vendor?.modules.map(module => (
                <SelectItem key={module} value={module}>
                  {module}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {vendor && (
        <div className="space-y-3">
          <div>
            <h4 className="text-sm font-medium mb-2">Field Mappings</h4>
            <div className="flex flex-wrap gap-2">
              {Object.entries(vendor.fields).slice(0, 6).map(([key, value]) => (
                <Badge key={key} variant="secondary" className="text-xs">
                  {key}: {value}
                </Badge>
              ))}
              {Object.keys(vendor.fields).length > 6 && (
                <Badge variant="outline" className="text-xs">
                  +{Object.keys(vendor.fields).length - 6} more
                </Badge>
              )}
            </div>
          </div>

          {validation && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium">CPS Validation</h4>
              
              {validation.valid ? (
                <Alert>
                  <CheckCircle className="h-4 w-4" />
                  <AlertDescription>
                    Query passes CPS validation checks
                  </AlertDescription>
                </Alert>
              ) : (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    <div className="space-y-1">
                      <div>CPS validation warnings:</div>
                      <ul className="list-disc list-inside text-xs space-y-1">
                        {validation.warnings.map((warning, idx) => (
                          <li key={idx}>{warning}</li>
                        ))}
                      </ul>
                    </div>
                  </AlertDescription>
                </Alert>
              )}
            </div>
          )}

          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription className="text-xs">
              CPS (CrowdStrike Platform Standard) ensures proper data classification and field normalization across vendors.
            </AlertDescription>
          </Alert>
        </div>
      )}
    </div>
  );
};