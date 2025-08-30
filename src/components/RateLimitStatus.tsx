import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { Button } from './ui/button';
import { Activity, Clock, AlertTriangle, CheckCircle } from 'lucide-react';
import { rateLimiter } from '../lib/rate-limiter';

interface RateLimitStatusProps {
  className?: string;
}

export function RateLimitStatus({ className }: RateLimitStatusProps) {
  const [status, setStatus] = useState<Record<string, any>>({});
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const updateStatus = () => {
      const allStatus = rateLimiter.getAllQueueStatus();
      setStatus(allStatus);
      
      // Show status if there are active requests or queued items
      const hasActivity = Object.values(allStatus).some(
        s => s.activeRequests > 0 || s.queueLength > 0
      );
      setIsVisible(hasActivity);
    };

    // Update immediately
    updateStatus();

    // Update every 2 seconds
    const interval = setInterval(updateStatus, 2000);

    return () => clearInterval(interval);
  }, []);

  if (!isVisible) return null;

  const getStatusColor = (providerStatus: any) => {
    if (!providerStatus.canMakeRequest) return 'destructive';
    if (providerStatus.activeRequests > 0) return 'default';
    return 'secondary';
  };

  const getStatusIcon = (providerStatus: any) => {
    if (!providerStatus.canMakeRequest) return <AlertTriangle className="h-4 w-4" />;
    if (providerStatus.activeRequests > 0) return <Activity className="h-4 w-4" />;
    return <CheckCircle className="h-4 w-4" />;
  };

  return (
    <Card className={`fixed bottom-4 right-4 w-80 z-50 ${className}`}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Activity className="h-4 w-4" />
          API Rate Limit Status
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {Object.entries(status).map(([provider, providerStatus]: [string, any]) => {
          if (providerStatus.activeRequests === 0 && providerStatus.queueLength === 0) {
            return null;
          }

          const utilizationPercent = Math.min(
            (providerStatus.recentRequests / 50) * 100, // Assuming 50 as typical max
            100
          );

          return (
            <div key={provider} className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {getStatusIcon(providerStatus)}
                  <span className="font-medium capitalize">{provider}</span>
                  <Badge variant={getStatusColor(providerStatus)} className="text-xs">
                    {providerStatus.canMakeRequest ? 'Active' : 'Limited'}
                  </Badge>
                </div>
              </div>

              {providerStatus.activeRequests > 0 && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Activity className="h-3 w-3" />
                  <span>{providerStatus.activeRequests} active request{providerStatus.activeRequests !== 1 ? 's' : ''}</span>
                </div>
              )}

              {providerStatus.queueLength > 0 && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  <span>{providerStatus.queueLength} queued</span>
                </div>
              )}

              {utilizationPercent > 0 && (
                <div className="space-y-1">
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>Rate limit usage</span>
                    <span>{Math.round(utilizationPercent)}%</span>
                  </div>
                  <Progress value={utilizationPercent} className="h-1" />
                </div>
              )}
            </div>
          );
        })}

        <div className="pt-2 border-t">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsVisible(false)}
            className="w-full text-xs"
          >
            Hide Status
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
