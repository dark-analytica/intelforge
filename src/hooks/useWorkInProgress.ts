import { useState, useEffect, useCallback } from 'react';

// Simple debounce implementation to avoid external dependency
function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) & { cancel: () => void } {
  let timeout: NodeJS.Timeout;
  
  const debounced = (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
  
  debounced.cancel = () => {
    clearTimeout(timeout);
  };
  
  return debounced;
}

interface WorkInProgressData {
  timestamp: number;
  data: any;
  version: string;
}

interface UseWorkInProgressOptions {
  key: string;
  debounceMs?: number;
  maxAge?: number; // in milliseconds
  version?: string;
}

export const useWorkInProgress = <T>({
  key,
  debounceMs = 1000,
  maxAge = 24 * 60 * 60 * 1000, // 24 hours default
  version = '1.0'
}: UseWorkInProgressOptions) => {
  const [data, setData] = useState<T | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);

  const storageKey = `cqlforge_wip_${key}`;

  // Load data from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const parsed: WorkInProgressData = JSON.parse(stored);
        
        // Check if data is not expired and version matches
        const now = Date.now();
        const isExpired = now - parsed.timestamp > maxAge;
        const isVersionMismatch = parsed.version !== version;
        
        if (!isExpired && !isVersionMismatch) {
          setData(parsed.data);
          setLastSaved(new Date(parsed.timestamp));
        } else {
          // Clean up expired or incompatible data
          localStorage.removeItem(storageKey);
        }
      }
    } catch (error) {
      console.warn('Failed to load work in progress:', error);
      localStorage.removeItem(storageKey);
    } finally {
      setIsLoaded(true);
    }
  }, [storageKey, maxAge, version]);

  // Debounced save function
  const debouncedSave = useCallback(
    debounce((dataToSave: T) => {
      try {
        const wipData: WorkInProgressData = {
          timestamp: Date.now(),
          data: dataToSave,
          version
        };
        localStorage.setItem(storageKey, JSON.stringify(wipData));
        setLastSaved(new Date());
      } catch (error) {
        console.error('Failed to save work in progress:', error);
      }
    }, debounceMs),
    [storageKey, version, debounceMs]
  );

  // Save data
  const saveData = useCallback((newData: T) => {
    setData(newData);
    if (newData !== null && newData !== undefined) {
      debouncedSave(newData);
    }
  }, [debouncedSave]);

  // Clear saved data
  const clearData = useCallback(() => {
    setData(null);
    setLastSaved(null);
    localStorage.removeItem(storageKey);
    debouncedSave.cancel();
  }, [storageKey, debouncedSave]);

  // Force immediate save
  const forceSave = useCallback(() => {
    if (data !== null && data !== undefined) {
      debouncedSave.cancel();
      try {
        const wipData: WorkInProgressData = {
          timestamp: Date.now(),
          data,
          version
        };
        localStorage.setItem(storageKey, JSON.stringify(wipData));
        setLastSaved(new Date());
      } catch (error) {
        console.error('Failed to force save work in progress:', error);
      }
    }
  }, [data, storageKey, version, debouncedSave]);

  // Check if there's saved data available
  const hasSavedData = data !== null && data !== undefined;

  return {
    data,
    isLoaded,
    lastSaved,
    hasSavedData,
    saveData,
    clearData,
    forceSave
  };
};
