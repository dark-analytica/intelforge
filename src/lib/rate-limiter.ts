/**
 * Rate limiter and request queue for API calls
 * Prevents API throttling and manages concurrent requests
 */

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  maxConcurrent: number;
  retryDelay: number;
  maxRetries: number;
}

export interface QueuedRequest<T> {
  id: string;
  execute: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  retryCount: number;
  priority: number;
  timestamp: number;
}

export class RateLimiter {
  private requests: Array<{ timestamp: number; provider: string }> = [];
  private queues: Map<string, QueuedRequest<any>[]> = new Map();
  private activeRequests: Map<string, number> = new Map();
  private configs: Map<string, RateLimitConfig> = new Map();

  constructor() {
    // Default configurations for different providers
    this.setProviderConfig('openai', {
      maxRequests: 50,
      windowMs: 60000, // 1 minute
      maxConcurrent: 5,
      retryDelay: 2000,
      maxRetries: 3
    });

    this.setProviderConfig('anthropic', {
      maxRequests: 40,
      windowMs: 60000,
      maxConcurrent: 4,
      retryDelay: 2500,
      maxRetries: 3
    });

    this.setProviderConfig('google', {
      maxRequests: 60,
      windowMs: 60000,
      maxConcurrent: 6,
      retryDelay: 1500,
      maxRetries: 3
    });

    this.setProviderConfig('openrouter', {
      maxRequests: 100,
      windowMs: 60000,
      maxConcurrent: 8,
      retryDelay: 1000,
      maxRetries: 3
    });

    // Clean up old requests periodically
    setInterval(() => this.cleanupOldRequests(), 30000);
  }

  setProviderConfig(provider: string, config: RateLimitConfig): void {
    this.configs.set(provider, config);
    if (!this.queues.has(provider)) {
      this.queues.set(provider, []);
    }
    if (!this.activeRequests.has(provider)) {
      this.activeRequests.set(provider, 0);
    }
  }

  async executeRequest<T>(
    provider: string,
    requestFn: () => Promise<T>,
    priority: number = 0
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const requestId = this.generateRequestId();
      const queuedRequest: QueuedRequest<T> = {
        id: requestId,
        execute: requestFn,
        resolve,
        reject,
        retryCount: 0,
        priority,
        timestamp: Date.now()
      };

      this.enqueueRequest(provider, queuedRequest);
      this.processQueue(provider);
    });
  }

  private enqueueRequest<T>(provider: string, request: QueuedRequest<T>): void {
    const queue = this.queues.get(provider) || [];
    
    // Insert request based on priority (higher priority first)
    const insertIndex = queue.findIndex(r => r.priority < request.priority);
    if (insertIndex === -1) {
      queue.push(request);
    } else {
      queue.splice(insertIndex, 0, request);
    }
    
    this.queues.set(provider, queue);
  }

  private async processQueue(provider: string): Promise<void> {
    const config = this.configs.get(provider);
    const queue = this.queues.get(provider);
    const activeCount = this.activeRequests.get(provider) || 0;

    if (!config || !queue || queue.length === 0 || activeCount >= config.maxConcurrent) {
      return;
    }

    if (!this.canMakeRequest(provider)) {
      // Wait and try again
      setTimeout(() => this.processQueue(provider), config.retryDelay);
      return;
    }

    const request = queue.shift();
    if (!request) return;

    this.activeRequests.set(provider, activeCount + 1);
    this.recordRequest(provider);

    try {
      const result = await request.execute();
      request.resolve(result);
    } catch (error) {
      await this.handleRequestError(provider, request, error as Error);
    } finally {
      this.activeRequests.set(provider, (this.activeRequests.get(provider) || 1) - 1);
      // Process next request in queue
      setTimeout(() => this.processQueue(provider), 100);
    }
  }

  private async handleRequestError<T>(
    provider: string,
    request: QueuedRequest<T>,
    error: Error
  ): Promise<void> {
    const config = this.configs.get(provider);
    if (!config) {
      request.reject(error);
      return;
    }

    // Check if error is retryable
    if (this.isRetryableError(error) && request.retryCount < config.maxRetries) {
      request.retryCount++;
      
      // Exponential backoff
      const delay = config.retryDelay * Math.pow(2, request.retryCount - 1);
      
      setTimeout(() => {
        this.enqueueRequest(provider, request);
        this.processQueue(provider);
      }, delay);
    } else {
      request.reject(error);
    }
  }

  private isRetryableError(error: Error): boolean {
    const retryableMessages = [
      'rate limit',
      'too many requests',
      'quota exceeded',
      'service unavailable',
      'timeout',
      'network error',
      'connection reset'
    ];

    const errorMessage = error.message.toLowerCase();
    return retryableMessages.some(msg => errorMessage.includes(msg));
  }

  private canMakeRequest(provider: string): boolean {
    const config = this.configs.get(provider);
    if (!config) return true;

    const now = Date.now();
    const windowStart = now - config.windowMs;
    
    const recentRequests = this.requests.filter(
      r => r.provider === provider && r.timestamp > windowStart
    );

    return recentRequests.length < config.maxRequests;
  }

  private recordRequest(provider: string): void {
    this.requests.push({
      timestamp: Date.now(),
      provider
    });
  }

  private cleanupOldRequests(): void {
    const now = Date.now();
    const maxAge = Math.max(...Array.from(this.configs.values()).map(c => c.windowMs));
    
    this.requests = this.requests.filter(
      r => now - r.timestamp < maxAge * 2
    );
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Utility methods for monitoring
  getQueueStatus(provider: string): {
    queueLength: number;
    activeRequests: number;
    canMakeRequest: boolean;
    recentRequests: number;
  } {
    const config = this.configs.get(provider);
    const queue = this.queues.get(provider) || [];
    const activeCount = this.activeRequests.get(provider) || 0;
    
    let recentRequests = 0;
    if (config) {
      const windowStart = Date.now() - config.windowMs;
      recentRequests = this.requests.filter(
        r => r.provider === provider && r.timestamp > windowStart
      ).length;
    }

    return {
      queueLength: queue.length,
      activeRequests: activeCount,
      canMakeRequest: this.canMakeRequest(provider),
      recentRequests
    };
  }

  getAllQueueStatus(): Record<string, ReturnType<typeof this.getQueueStatus>> {
    const status: Record<string, ReturnType<typeof this.getQueueStatus>> = {};
    
    for (const provider of this.configs.keys()) {
      status[provider] = this.getQueueStatus(provider);
    }
    
    return status;
  }

  clearQueue(provider: string): void {
    const queue = this.queues.get(provider) || [];
    queue.forEach(request => {
      request.reject(new Error('Queue cleared'));
    });
    this.queues.set(provider, []);
  }

  clearAllQueues(): void {
    for (const provider of this.queues.keys()) {
      this.clearQueue(provider);
    }
  }
}

// Global rate limiter instance
export const rateLimiter = new RateLimiter();
