import React from 'react';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Save, Clock, Trash2, AlertTriangle } from 'lucide-react';
// Simple time formatting function to avoid external dependency
function formatDistanceToNow(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
}

interface WorkInProgressIndicatorProps {
  lastSaved: Date | null;
  hasSavedData: boolean;
  onRestore: () => void;
  onClear: () => void;
  onForceSave: () => void;
  className?: string;
}

export const WorkInProgressIndicator: React.FC<WorkInProgressIndicatorProps> = ({
  lastSaved,
  hasSavedData,
  onRestore,
  onClear,
  onForceSave,
  className
}) => {
  if (!hasSavedData && !lastSaved) {
    return null;
  }

  return (
    <Alert className={className}>
      <AlertTriangle className="h-4 w-4" />
      <AlertDescription className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span>Work in progress detected</span>
          {lastSaved && (
            <Badge variant="secondary" className="text-xs">
              <Clock className="h-3 w-3 mr-1" />
              Saved {formatDistanceToNow(lastSaved)}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onRestore}
            className="h-7 px-2 text-xs"
          >
            Restore
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={onForceSave}
            className="h-7 px-2 text-xs"
          >
            <Save className="h-3 w-3 mr-1" />
            Save
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={onClear}
            className="h-7 px-2 text-xs text-destructive hover:text-destructive"
          >
            <Trash2 className="h-3 w-3 mr-1" />
            Clear
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
};
