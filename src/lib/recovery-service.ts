// Recovery Service for handling errors and implementing fallback mechanisms
import { analytics } from './analytics';

export interface RecoveryStrategy {
  name: string;
  condition: (error: Error) => boolean;
  recover: () => Promise<void>;
  maxRetries?: number;
}

export class RecoveryService {
  private strategies: RecoveryStrategy[] = [];
  private retryAttempts = new Map<string, number>();

  constructor() {
    this.registerDefaultStrategies();
  }

  private registerDefaultStrategies() {
    // Network error recovery
    this.addStrategy({
      name: 'network-retry',
      condition: (error) => 
        error.message.includes('fetch') || 
        error.message.includes('network') ||
        error.message.includes('Failed to fetch'),
      recover: async () => {
        await this.delay(1000); // Wait 1 second before retry
      },
      maxRetries: 3
    });

    // API key error recovery
    this.addStrategy({
      name: 'api-key-fallback',
      condition: (error) => 
        error.message.includes('API key') ||
        error.message.includes('unauthorized') ||
        error.message.includes('401'),
      recover: async () => {
        // Clear potentially corrupted API keys
        const keysToCheck = ['openai_api_key', 'anthropic_api_key', 'gemini_api_key', 'openrouter_api_key'];
        for (const key of keysToCheck) {
          try {
            const stored = localStorage.getItem(key);
            if (stored && (stored.length < 10 || stored.includes('undefined'))) {
              localStorage.removeItem(key);
            }
          } catch (e) {
            console.warn(`Failed to check API key ${key}:`, e);
          }
        }
      },
      maxRetries: 1
    });

    // Storage error recovery
    this.addStrategy({
      name: 'storage-fallback',
      condition: (error) => 
        error.message.includes('localStorage') ||
        error.message.includes('QuotaExceededError') ||
        error.message.includes('storage'),
      recover: async () => {
        try {
          // Clear old analytics data to free up space
          const keys = Object.keys(localStorage);
          const analyticsKeys = keys.filter(key => key.startsWith('analytics_'));
          analyticsKeys.forEach(key => localStorage.removeItem(key));
          
          // Clear old cached data
          const cacheKeys = keys.filter(key => key.startsWith('cache_'));
          cacheKeys.forEach(key => localStorage.removeItem(key));
        } catch (e) {
          console.warn('Failed to clear storage:', e);
        }
      },
      maxRetries: 1
    });

    // Memory leak recovery
    this.addStrategy({
      name: 'memory-cleanup',
      condition: (error) => 
        error.message.includes('out of memory') ||
        error.message.includes('Maximum call stack'),
      recover: async () => {
        // Force garbage collection if available
        if (window.gc) {
          window.gc();
        }
        
        // Clear large objects from memory
        this.clearLargeObjects();
      },
      maxRetries: 2
    });
  }

  addStrategy(strategy: RecoveryStrategy) {
    this.strategies.push(strategy);
  }

  async handleError(error: Error, context?: string): Promise<boolean> {
    analytics.track('recovery_attempt', {
      error: error.message,
      context,
      timestamp: Date.now()
    });

    for (const strategy of this.strategies) {
      if (strategy.condition(error)) {
        const retryKey = `${strategy.name}-${error.message}`;
        const attempts = this.retryAttempts.get(retryKey) || 0;
        const maxRetries = strategy.maxRetries || 1;

        if (attempts < maxRetries) {
          try {
            console.log(`Attempting recovery with strategy: ${strategy.name}`);
            await strategy.recover();
            
            this.retryAttempts.set(retryKey, attempts + 1);
            
            analytics.track('recovery_success', {
              strategy: strategy.name,
              attempts: attempts + 1,
              error: error.message
            });
            
            return true;
          } catch (recoveryError) {
            console.error(`Recovery strategy ${strategy.name} failed:`, recoveryError);
            
            analytics.track('recovery_failed', {
              strategy: strategy.name,
              attempts: attempts + 1,
              error: error.message,
              recoveryError: (recoveryError as Error).message
            });
          }
        } else {
          console.log(`Max retries exceeded for strategy: ${strategy.name}`);
        }
      }
    }

    return false;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private clearLargeObjects() {
    // Clear any large cached objects that might be causing memory issues
    try {
      // Clear Monaco editor models if they exist
      const win = window as any;
      if (win.monaco?.editor) {
        const models = win.monaco.editor.getModels();
        models.forEach((model: any) => {
          if (model.getValueLength() > 50000) { // Clear large models
            model.dispose();
          }
        });
      }

      // Clear large DOM elements
      const largeElements = document.querySelectorAll('[data-large-content]');
      largeElements.forEach(element => {
        if (element.textContent && element.textContent.length > 100000) {
          element.textContent = '';
        }
      });
    } catch (e) {
      console.warn('Failed to clear large objects:', e);
    }
  }

  // Reset retry counters (useful after successful operations)
  resetRetries(strategyName?: string) {
    if (strategyName) {
      const keysToDelete = Array.from(this.retryAttempts.keys())
        .filter(key => key.startsWith(strategyName));
      keysToDelete.forEach(key => this.retryAttempts.delete(key));
    } else {
      this.retryAttempts.clear();
    }
  }

  // Get current retry status
  getRetryStatus(): Record<string, number> {
    const status: Record<string, number> = {};
    this.retryAttempts.forEach((attempts, key) => {
      status[key] = attempts;
    });
    return status;
  }
}

// Global recovery service instance
export const recoveryService = new RecoveryService();

// Enhanced error handler with recovery
export async function handleErrorWithRecovery(
  error: Error, 
  context?: string,
  fallbackAction?: () => void
): Promise<void> {
  console.error(`Error in ${context || 'unknown context'}:`, error);

  const recovered = await recoveryService.handleError(error, context);
  
  if (!recovered && fallbackAction) {
    console.log('Recovery failed, executing fallback action');
    fallbackAction();
  }
}

// Wrapper for async operations with automatic recovery
export async function withRecovery<T>(
  operation: () => Promise<T>,
  context: string,
  maxAttempts: number = 3
): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const result = await operation();
      
      // Reset retry counters on success
      if (attempt > 1) {
        recoveryService.resetRetries();
      }
      
      return result;
    } catch (error) {
      lastError = error as Error;
      
      if (attempt === maxAttempts) {
        break;
      }
      
      const recovered = await recoveryService.handleError(lastError, context);
      if (!recovered) {
        break;
      }
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  
  throw lastError!;
}
