import { useCallback } from 'react';
import { useToast } from '@/hooks/use-toast';

interface ErrorContext {
  component?: string;
  action?: string;
  details?: any;
}

interface ErrorInfo {
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'network' | 'validation' | 'processing' | 'storage' | 'auth' | 'unknown';
  retryable: boolean;
  userAction?: string;
}

export const useErrorHandler = () => {
  const { toast } = useToast();

  const categorizeError = useCallback((error: any, context?: ErrorContext): ErrorInfo => {
    const errorMessage = error.message || error.toString() || 'Unknown error occurred';
    
    // Network errors
    if (errorMessage.includes('fetch') || errorMessage.includes('network') || errorMessage.includes('offline')) {
      return {
        message: 'Network connection error. Please check your internet connection.',
        severity: 'high',
        category: 'network',
        retryable: true,
        userAction: 'Check your internet connection and try again.'
      };
    }

    // API errors
    if (errorMessage.includes('401') || errorMessage.includes('unauthorized')) {
      return {
        message: 'API authentication failed. Please check your API keys.',
        severity: 'high',
        category: 'auth',
        retryable: true,
        userAction: 'Go to Settings and verify your API keys are correct.'
      };
    }

    if (errorMessage.includes('429') || errorMessage.includes('rate limit')) {
      return {
        message: 'API rate limit exceeded. Please wait before trying again.',
        severity: 'medium',
        category: 'network',
        retryable: true,
        userAction: 'Wait a few minutes before making another request.'
      };
    }

    if (errorMessage.includes('403') || errorMessage.includes('forbidden')) {
      return {
        message: 'API access forbidden. Check your API key permissions.',
        severity: 'high',
        category: 'auth',
        retryable: false,
        userAction: 'Verify your API key has the necessary permissions.'
      };
    }

    // File processing errors
    if (errorMessage.includes('PDF') || errorMessage.includes('file')) {
      return {
        message: 'File processing error. The file may be corrupted or unsupported.',
        severity: 'medium',
        category: 'processing',
        retryable: true,
        userAction: 'Try a different file or check the file format.'
      };
    }

    // Storage errors
    if (errorMessage.includes('localStorage') || errorMessage.includes('storage')) {
      return {
        message: 'Browser storage error. Your data may not be saved.',
        severity: 'medium',
        category: 'storage',
        retryable: true,
        userAction: 'Clear browser cache or try in an incognito window.'
      };
    }

    // Validation errors
    if (errorMessage.includes('validation') || errorMessage.includes('invalid')) {
      return {
        message: 'Data validation error. Please check your input.',
        severity: 'low',
        category: 'validation',
        retryable: true,
        userAction: 'Review your input data for any errors.'
      };
    }

    // Memory/performance errors
    if (errorMessage.includes('memory') || errorMessage.includes('Maximum call stack')) {
      return {
        message: 'Processing limit exceeded. Try with smaller data sets.',
        severity: 'medium',
        category: 'processing',
        retryable: true,
        userAction: 'Reduce the amount of data being processed at once.'
      };
    }

    // Default categorization
    return {
      message: errorMessage,
      severity: 'medium',
      category: 'unknown',
      retryable: true,
      userAction: 'Try again or contact support if the issue persists.'
    };
  }, []);

  const handleError = useCallback((error: any, context?: ErrorContext) => {
    const errorInfo = categorizeError(error, context);
    
    // Log error for debugging
    console.error(`[${context?.component || 'Unknown'}] ${context?.action || 'Error'}:`, {
      error,
      context,
      errorInfo
    });

    // Analytics tracking (if enabled)
    const settings = localStorage.getItem('cqlforge_security_settings');
    const enableAnalytics = settings ? JSON.parse(settings).enableAnalytics : false;
    
    if (enableAnalytics) {
      // Track error occurrence (implement analytics service here)
      console.log('Error tracked:', {
        component: context?.component,
        action: context?.action,
        category: errorInfo.category,
        severity: errorInfo.severity
      });
    }

    // Show user-friendly toast
    const toastVariant = errorInfo.severity === 'critical' || errorInfo.severity === 'high' 
      ? 'destructive' 
      : 'default';

    toast({
      title: `${errorInfo.category.charAt(0).toUpperCase() + errorInfo.category.slice(1)} Error`,
      description: errorInfo.message,
      variant: toastVariant
    });

    // Show additional help if available
    if (errorInfo.userAction) {
      setTimeout(() => {
        toast({
          title: 'Recommended Action',
          description: errorInfo.userAction
        });
      }, 2000);
    }

    return errorInfo;
  }, [categorizeError, toast]);

  const handleAsyncError = useCallback(async <T>(
    asyncFn: () => Promise<T>,
    context?: ErrorContext
  ): Promise<T | null> => {
    try {
      return await asyncFn();
    } catch (error) {
      handleError(error, context);
      return null;
    }
  }, [handleError]);

  const withRetry = useCallback(async <T>(
    asyncFn: () => Promise<T>,
    maxRetries: number = 3,
    delayMs: number = 1000,
    context?: ErrorContext
  ): Promise<T | null> => {
    let lastError: any;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await asyncFn();
      } catch (error) {
        lastError = error;
        const errorInfo = categorizeError(error, context);
        
        if (!errorInfo.retryable || attempt === maxRetries) {
          handleError(error, { ...context, action: `${context?.action} (failed after ${attempt + 1} attempts)` });
          break;
        }

        // Wait before retrying
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, delayMs * Math.pow(2, attempt)));
        }
      }
    }
    
    return null;
  }, [categorizeError, handleError]);

  return {
    handleError,
    handleAsyncError,
    withRetry,
    categorizeError
  };
};