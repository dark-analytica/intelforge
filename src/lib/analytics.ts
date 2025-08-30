// Analytics and Usage Tracking (Local Only)
interface AnalyticsEvent {
  event: string;
  component?: string;
  properties?: Record<string, any>;
  timestamp: number;
}

interface UsageStats {
  iocsExtracted: number;
  queriesGenerated: number;
  exportsCreated: number;
  errorsEncountered: number;
  sessionDuration: number;
  lastActive: number;
}

class AnalyticsService {
  private events: AnalyticsEvent[] = [];
  private sessionStart: number;
  private isEnabled: boolean = false;
  private cleanupInterval: number | null = null;
  private beforeUnloadHandler: (() => void) | null = null;

  constructor() {
    this.sessionStart = Date.now();
    this.loadSettings();
    this.setupBeforeUnload();
    this.setupPeriodicCleanup();
  }

  private loadSettings() {
    try {
      const settings = localStorage.getItem('cqlforge_security_settings');
      if (settings) {
        const parsed = JSON.parse(settings);
        this.isEnabled = parsed.enableAnalytics || false;
      }
    } catch (error) {
      console.warn('Failed to load analytics settings:', error);
    }
  }

  private setupBeforeUnload() {
    this.beforeUnloadHandler = () => {
      this.updateSessionDuration();
    };
    window.addEventListener('beforeunload', this.beforeUnloadHandler);
  }

  private setupPeriodicCleanup() {
    // Clean up old data every 5 minutes
    this.cleanupInterval = window.setInterval(() => {
      this.cleanupOldData();
    }, 5 * 60 * 1000);
  }

  private cleanupOldData() {
    try {
      // Remove events older than 30 days
      const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
      this.events = this.events.filter(event => event.timestamp > thirtyDaysAgo);
      
      // Clean up localStorage if it's getting too large
      const eventsData = localStorage.getItem('cqlforge_analytics_events');
      if (eventsData && eventsData.length > 500000) { // 500KB limit
        const events = JSON.parse(eventsData);
        const recentEvents = events.slice(-500); // Keep only last 500 events
        localStorage.setItem('cqlforge_analytics_events', JSON.stringify(recentEvents));
        this.events = recentEvents;
      }
    } catch (error) {
      console.warn('Failed to cleanup old analytics data:', error);
    }
  }

  // Cleanup method to prevent memory leaks
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    
    if (this.beforeUnloadHandler) {
      window.removeEventListener('beforeunload', this.beforeUnloadHandler);
      this.beforeUnloadHandler = null;
    }
    
    this.events = [];
  }

  private updateSessionDuration() {
    if (!this.isEnabled) return;
    
    try {
      const stats = this.getUsageStats();
      stats.sessionDuration = Date.now() - this.sessionStart;
      stats.lastActive = Date.now();
      localStorage.setItem('cqlforge_usage_stats', JSON.stringify(stats));
    } catch (error) {
      console.warn('Failed to update session duration:', error);
    }
  }

  track(event: string, properties?: Record<string, any>, component?: string) {
    if (!this.isEnabled) return;

    try {
      const analyticsEvent: AnalyticsEvent = {
        event,
        component,
        properties,
        timestamp: Date.now()
      };

      this.events.push(analyticsEvent);
      this.updateUsageStats(event, properties);

      // Keep only last 1000 events to prevent memory issues
      if (this.events.length > 1000) {
        this.events = this.events.slice(-1000);
      }

      // Persist events
      localStorage.setItem('cqlforge_analytics_events', JSON.stringify(this.events));
    } catch (error) {
      console.warn('Analytics tracking failed:', error);
    }
  }

  private updateUsageStats(event: string, properties?: Record<string, any>) {
    try {
      const stats = this.getUsageStats();
      
      switch (event) {
        case 'iocs_extracted':
          stats.iocsExtracted += properties?.count || 1;
          break;
        case 'query_generated':
          stats.queriesGenerated += 1;
          break;
        case 'export_created':
          stats.exportsCreated += 1;
          break;
        case 'error_occurred':
          stats.errorsEncountered += 1;
          break;
      }

      stats.lastActive = Date.now();
      localStorage.setItem('cqlforge_usage_stats', JSON.stringify(stats));
    } catch (error) {
      console.warn('Failed to update usage stats:', error);
    }
  }

  getUsageStats(): UsageStats {
    try {
      const stored = localStorage.getItem('cqlforge_usage_stats');
      if (stored) {
        return { ...this.getDefaultStats(), ...JSON.parse(stored) };
      }
    } catch (error) {
      console.warn('Failed to load usage stats:', error);
    }
    
    return this.getDefaultStats();
  }

  private getDefaultStats(): UsageStats {
    return {
      iocsExtracted: 0,
      queriesGenerated: 0,
      exportsCreated: 0,
      errorsEncountered: 0,
      sessionDuration: 0,
      lastActive: Date.now()
    };
  }

  getEvents(limit?: number): AnalyticsEvent[] {
    try {
      const stored = localStorage.getItem('cqlforge_analytics_events');
      if (stored) {
        const events = JSON.parse(stored);
        return limit ? events.slice(-limit) : events;
      }
    } catch (error) {
      console.warn('Failed to load analytics events:', error);
    }
    
    return [];
  }

  getEventsSummary(timeframe: 'hour' | 'day' | 'week' | 'month' = 'day') {
    const events = this.getEvents();
    const now = Date.now();
    
    const timeframes = {
      hour: 60 * 60 * 1000,
      day: 24 * 60 * 60 * 1000,
      week: 7 * 24 * 60 * 60 * 1000,
      month: 30 * 24 * 60 * 60 * 1000
    };

    const cutoff = now - timeframes[timeframe];
    const recentEvents = events.filter(event => event.timestamp > cutoff);

    const summary = recentEvents.reduce((acc, event) => {
      acc[event.event] = (acc[event.event] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      timeframe,
      period: new Date(cutoff).toISOString(),
      total: recentEvents.length,
      events: summary
    };
  }

  clearData() {
    try {
      localStorage.removeItem('cqlforge_analytics_events');
      localStorage.removeItem('cqlforge_usage_stats');
      this.events = [];
    } catch (error) {
      console.warn('Failed to clear analytics data:', error);
    }
  }

  enable() {
    this.isEnabled = true;
    this.track('analytics_enabled');
  }

  disable() {
    this.isEnabled = false;
    this.clearData();
  }

  exportData() {
    try {
      const data = {
        events: this.getEvents(),
        stats: this.getUsageStats(),
        summary: {
          last_hour: this.getEventsSummary('hour'),
          last_day: this.getEventsSummary('day'),
          last_week: this.getEventsSummary('week'),
          last_month: this.getEventsSummary('month')
        },
        exported_at: new Date().toISOString()
      };

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cqlforge-analytics-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      return true;
    } catch (error) {
      console.error('Failed to export analytics data:', error);
      return false;
    }
  }
}

// Singleton instance
export const analytics = new AnalyticsService();

// Convenience functions for common tracking
export const trackIOCExtraction = (count: number, source: string) => {
  analytics.track('iocs_extracted', { count, source }, 'IOCExtractor');
};

export const trackQueryGeneration = (vendor: string, template: string, iocTypes: string[]) => {
  analytics.track('query_generated', { vendor, template, iocTypes }, 'CQLGenerator');
};

export const trackExport = (format: string, iocCount: number, hasQueries: boolean) => {
  analytics.track('export_created', { format, iocCount, hasQueries }, 'ExportDialog');
};

export const trackError = (component: string, action: string, errorType: string) => {
  analytics.track('error_occurred', { component, action, errorType });
};

export const trackUserAction = (action: string, component: string, details?: Record<string, any>) => {
  analytics.track('user_action', { action, ...details }, component);
};

export const trackAIUsage = (provider: string, feature: string, tokensUsed?: number) => {
  analytics.track('ai_usage', { provider, feature, tokensUsed }, 'AI');
};

export const trackPerformance = (operation: string, duration: number, dataSize?: number) => {
  analytics.track('performance', { operation, duration, dataSize });
};

export interface LLMCallMetrics {
  provider: string;
  model: string;
  success: boolean;
  responseTime: number;
  tokenCount?: number;
  error?: string;
}

export const trackLLMCall = (metrics: LLMCallMetrics) => {
  analytics.track('llm_call', metrics, 'LLMService');
};
