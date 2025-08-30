/**
 * Batch Processing Engine for Large IOC Sets
 * Handles efficient processing of large datasets with chunking, progress tracking, and memory management
 */

export interface BatchConfig {
  batchSize: number;
  maxConcurrency: number;
  delayBetweenBatches: number;
  enableProgressTracking: boolean;
  memoryThreshold: number; // MB
}

export interface BatchProgress {
  totalItems: number;
  processedItems: number;
  currentBatch: number;
  totalBatches: number;
  percentage: number;
  estimatedTimeRemaining: number;
  throughput: number; // items per second
  errors: BatchError[];
}

export interface BatchError {
  batchIndex: number;
  itemIndex: number;
  error: string;
  timestamp: number;
}

export interface BatchResult<T> {
  results: T[];
  errors: BatchError[];
  totalProcessed: number;
  totalTime: number;
  averageThroughput: number;
}

export type BatchProcessor<T, R> = (items: T[], batchIndex: number) => Promise<R[]>;
export type ProgressCallback = (progress: BatchProgress) => void;

export class BatchProcessingEngine {
  private defaultConfig: BatchConfig = {
    batchSize: 100,
    maxConcurrency: 3,
    delayBetweenBatches: 100,
    enableProgressTracking: true,
    memoryThreshold: 500 // 500MB
  };

  private activeProcesses = new Set<string>();
  private memoryMonitor: NodeJS.Timeout | null = null;

  async processBatch<T, R>(
    items: T[],
    processor: BatchProcessor<T, R>,
    config: Partial<BatchConfig> = {},
    onProgress?: ProgressCallback
  ): Promise<BatchResult<R>> {
    const finalConfig = { ...this.defaultConfig, ...config };
    const processId = this.generateProcessId();
    
    this.activeProcesses.add(processId);
    
    try {
      return await this.executeBatchProcessing(
        items,
        processor,
        finalConfig,
        onProgress,
        processId
      );
    } finally {
      this.activeProcesses.delete(processId);
    }
  }

  private async executeBatchProcessing<T, R>(
    items: T[],
    processor: BatchProcessor<T, R>,
    config: BatchConfig,
    onProgress?: ProgressCallback,
    processId?: string
  ): Promise<BatchResult<R>> {
    const startTime = Date.now();
    const batches = this.createBatches(items, config.batchSize);
    const results: R[] = [];
    const errors: BatchError[] = [];
    
    let processedItems = 0;
    const totalItems = items.length;
    const totalBatches = batches.length;

    // Start memory monitoring if enabled
    if (config.memoryThreshold > 0) {
      this.startMemoryMonitoring(config.memoryThreshold);
    }

    // Process batches with concurrency control
    const semaphore = new Semaphore(config.maxConcurrency);
    const batchPromises: Promise<void>[] = [];

    for (let i = 0; i < batches.length; i++) {
      const batchPromise = semaphore.acquire().then(async (release) => {
        try {
          const batch = batches[i];
          const batchStartTime = Date.now();
          
          try {
            const batchResults = await processor(batch, i);
            results.push(...batchResults);
            processedItems += batch.length;

            // Update progress
            if (config.enableProgressTracking && onProgress) {
              const progress = this.calculateProgress(
                totalItems,
                processedItems,
                i + 1,
                totalBatches,
                startTime,
                errors
              );
              onProgress(progress);
            }

            // Delay between batches to prevent overwhelming
            if (config.delayBetweenBatches > 0 && i < batches.length - 1) {
              await this.delay(config.delayBetweenBatches);
            }

          } catch (error) {
            // Handle batch-level errors
            batch.forEach((_, itemIndex) => {
              errors.push({
                batchIndex: i,
                itemIndex: itemIndex + (i * config.batchSize),
                error: (error as Error).message,
                timestamp: Date.now()
              });
            });
          }
        } finally {
          release();
        }
      });

      batchPromises.push(batchPromise);
    }

    // Wait for all batches to complete
    await Promise.all(batchPromises);

    // Stop memory monitoring
    this.stopMemoryMonitoring();

    const totalTime = Date.now() - startTime;
    const averageThroughput = totalItems / (totalTime / 1000);

    return {
      results,
      errors,
      totalProcessed: processedItems,
      totalTime,
      averageThroughput
    };
  }

  private createBatches<T>(items: T[], batchSize: number): T[][] {
    const batches: T[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  private calculateProgress(
    totalItems: number,
    processedItems: number,
    currentBatch: number,
    totalBatches: number,
    startTime: number,
    errors: BatchError[]
  ): BatchProgress {
    const percentage = (processedItems / totalItems) * 100;
    const elapsedTime = Date.now() - startTime;
    const throughput = processedItems / (elapsedTime / 1000);
    const remainingItems = totalItems - processedItems;
    const estimatedTimeRemaining = throughput > 0 ? (remainingItems / throughput) * 1000 : 0;

    return {
      totalItems,
      processedItems,
      currentBatch,
      totalBatches,
      percentage,
      estimatedTimeRemaining,
      throughput,
      errors: [...errors]
    };
  }

  private startMemoryMonitoring(threshold: number): void {
    if (typeof performance !== 'undefined' && (performance as any).memory) {
      this.memoryMonitor = setInterval(() => {
        const memoryInfo = (performance as any).memory;
        const usedMemoryMB = memoryInfo.usedJSHeapSize / (1024 * 1024);
        
        if (usedMemoryMB > threshold) {
          console.warn(`Memory usage (${usedMemoryMB.toFixed(2)}MB) exceeds threshold (${threshold}MB)`);
          // Trigger garbage collection if available
          if (typeof gc !== 'undefined') {
            gc();
          }
        }
      }, 5000);
    }
  }

  private stopMemoryMonitoring(): void {
    if (this.memoryMonitor) {
      clearInterval(this.memoryMonitor);
      this.memoryMonitor = null;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private generateProcessId(): string {
    return `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Utility methods
  getActiveProcessCount(): number {
    return this.activeProcesses.size;
  }

  isProcessing(): boolean {
    return this.activeProcesses.size > 0;
  }

  // Optimized IOC processing methods
  async processIOCsInBatches(
    text: string,
    extractorFunction: (text: string) => any,
    config: Partial<BatchConfig> = {}
  ): Promise<BatchResult<any>> {
    // Split large text into manageable chunks
    const textChunks = this.splitTextIntoChunks(text, config.batchSize || 1000);
    
    return this.processBatch(
      textChunks,
      async (chunks: string[]) => {
        const results = [];
        for (const chunk of chunks) {
          try {
            const iocs = extractorFunction(chunk);
            results.push(iocs);
          } catch (error) {
            console.warn('Failed to process text chunk:', error);
            results.push({ ipv4: [], ipv6: [], domains: [], urls: [], sha256: [], md5: [], emails: [] });
          }
        }
        return results;
      },
      config
    );
  }

  private splitTextIntoChunks(text: string, chunkSize: number): string[] {
    const chunks: string[] = [];
    const lines = text.split('\n');
    let currentChunk = '';
    let lineCount = 0;

    for (const line of lines) {
      currentChunk += line + '\n';
      lineCount++;

      if (lineCount >= chunkSize) {
        chunks.push(currentChunk.trim());
        currentChunk = '';
        lineCount = 0;
      }
    }

    if (currentChunk.trim()) {
      chunks.push(currentChunk.trim());
    }

    return chunks;
  }

  // Merge IOC results from multiple batches
  mergeIOCResults(results: any[]): any {
    const merged = {
      ipv4: new Set<string>(),
      ipv6: new Set<string>(),
      domains: new Set<string>(),
      urls: new Set<string>(),
      sha256: new Set<string>(),
      md5: new Set<string>(),
      emails: new Set<string>()
    };

    results.forEach(result => {
      if (result && typeof result === 'object') {
        Object.keys(merged).forEach(key => {
          if (Array.isArray(result[key])) {
            result[key].forEach((item: string) => merged[key as keyof typeof merged].add(item));
          }
        });
      }
    });

    // Convert sets back to arrays
    return {
      ipv4: Array.from(merged.ipv4),
      ipv6: Array.from(merged.ipv6),
      domains: Array.from(merged.domains),
      urls: Array.from(merged.urls),
      sha256: Array.from(merged.sha256),
      md5: Array.from(merged.md5),
      emails: Array.from(merged.emails)
    };
  }
}

// Semaphore for concurrency control
class Semaphore {
  private permits: number;
  private waitQueue: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<() => void> {
    return new Promise((resolve) => {
      if (this.permits > 0) {
        this.permits--;
        resolve(() => this.release());
      } else {
        this.waitQueue.push(() => {
          this.permits--;
          resolve(() => this.release());
        });
      }
    });
  }

  private release(): void {
    this.permits++;
    if (this.waitQueue.length > 0) {
      const next = this.waitQueue.shift();
      if (next) next();
    }
  }
}

// Export singleton instance
export const batchProcessor = new BatchProcessingEngine();
