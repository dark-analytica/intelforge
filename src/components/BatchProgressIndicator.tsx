import React from 'react';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Clock, Zap, AlertTriangle } from 'lucide-react';

interface BatchProgressProps {
  totalItems: number;
  processedItems: number;
  currentBatch: number;
  totalBatches: number;
  percentage: number;
  estimatedTimeRemaining: number;
  throughput: number;
  errors: Array<{
    batchIndex: number;
    itemIndex: number;
    error: string;
    timestamp: number;
  }>;
  isVisible: boolean;
}

export const BatchProgressIndicator: React.FC<BatchProgressProps> = ({
  totalItems,
  processedItems,
  currentBatch,
  totalBatches,
  percentage,
  estimatedTimeRemaining,
  throughput,
  errors,
  isVisible
}) => {
  if (!isVisible) return null;

  const formatTime = (ms: number): string => {
    if (ms < 1000) return `${Math.round(ms)}ms`;
    if (ms < 60000) return `${Math.round(ms / 1000)}s`;
    return `${Math.round(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
  };

  const formatThroughput = (itemsPerSecond: number): string => {
    if (itemsPerSecond < 1) return `${(itemsPerSecond * 60).toFixed(1)}/min`;
    return `${itemsPerSecond.toFixed(1)}/s`;
  };

  return (
    <Card className="w-full max-w-md mx-auto bg-background/95 backdrop-blur border-primary/20">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Zap className="h-4 w-4 text-primary" />
          Batch Processing
          <Badge variant="outline" className="ml-auto">
            {currentBatch}/{totalBatches}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>{processedItems.toLocaleString()} / {totalItems.toLocaleString()} items</span>
            <span>{percentage.toFixed(1)}%</span>
          </div>
          <Progress value={percentage} className="h-2" />
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex items-center gap-2">
            <Clock className="h-3 w-3 text-muted-foreground" />
            <div>
              <div className="text-muted-foreground">ETA</div>
              <div className="font-medium">
                {estimatedTimeRemaining > 0 ? formatTime(estimatedTimeRemaining) : '--'}
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <Zap className="h-3 w-3 text-muted-foreground" />
            <div>
              <div className="text-muted-foreground">Speed</div>
              <div className="font-medium">{formatThroughput(throughput)}</div>
            </div>
          </div>
        </div>

        {/* Error Indicator */}
        {errors.length > 0 && (
          <div className="flex items-center gap-2 p-2 bg-destructive/10 rounded-md">
            <AlertTriangle className="h-4 w-4 text-destructive" />
            <div className="text-xs">
              <div className="text-destructive font-medium">
                {errors.length} error{errors.length !== 1 ? 's' : ''}
              </div>
              <div className="text-muted-foreground">
                Latest: {errors[errors.length - 1]?.error.slice(0, 40)}...
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
