// Lazy loading utilities for code splitting and bundle optimization
import { lazy } from 'react';

// Lazy load heavy components
export const LazyMonacoEditor = lazy(() => 
  import('@monaco-editor/react').then(module => ({
    default: module.Editor
  }))
);

export const LazyApiKeysDialog = lazy(() => 
  import('../components/ApiKeysDialog').then(module => ({
    default: module.ApiKeysDialog
  }))
);

export const LazyTTPExtractor = lazy(() => 
  import('../components/TTpExtractor').then(module => ({
    default: module.TTpExtractor
  }))
);

export const LazyHuntPackManager = lazy(() => 
  import('../components/HuntPackManager').then(module => ({
    default: module.HuntPackManager
  }))
);

// Lazy load analytics service only when needed
export const loadAnalytics = () => 
  import('./analytics').then(module => module.analytics);

// Lazy load recovery service only when needed
export const loadRecoveryService = () => 
  import('./recovery-service').then(module => module.recoveryService);

// Preload critical components after initial render
export const preloadCriticalComponents = () => {
  // Preload Monaco Editor after a delay
  setTimeout(() => {
    import('@monaco-editor/react');
  }, 2000);

  // Preload other heavy components
  setTimeout(() => {
    import('../components/ApiKeysDialog');
    import('../components/TTpExtractor');
  }, 5000);
};

// Dynamic import wrapper with error handling
export async function dynamicImport<T>(
  importFn: () => Promise<T>,
  fallback?: T,
  retries: number = 3
): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await importFn();
    } catch (error) {
      lastError = error as Error;
      
      if (attempt === retries) {
        console.error(`Failed to load module after ${retries} attempts:`, lastError);
        if (fallback !== undefined) {
          return fallback;
        }
        throw lastError;
      }
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  
  throw lastError!;
}
