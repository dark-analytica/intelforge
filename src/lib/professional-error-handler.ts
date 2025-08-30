/**
 * Professional error handling system for IntelForge
 * Provides specific, actionable error messages for security professionals
 */

export interface ProfessionalError {
  code: string;
  title: string;
  message: string;
  action?: string;
  documentation?: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  context?: Record<string, any>;
}

export const ERROR_CODES = {
  // API and Rate Limiting Errors
  API_RATE_LIMIT_EXCEEDED: {
    title: 'API Rate Limit Exceeded',
    message: 'You\'ve reached the hourly rate limit for this AI provider.',
    action: 'Switch to a different AI provider in Settings or wait 1 hour before retrying.',
    severity: 'warning' as const
  },
  
  API_KEY_INVALID: {
    title: 'Invalid API Key',
    message: 'The API key for this provider is invalid or has expired.',
    action: 'Update your API key in Settings → Configure API Keys.',
    documentation: '/docs/setup#api-keys',
    severity: 'error' as const
  },
  
  API_PROVIDER_UNAVAILABLE: {
    title: 'AI Provider Unavailable',
    message: 'The selected AI provider is currently unavailable.',
    action: 'Try switching to a different provider or use offline mode for basic features.',
    severity: 'warning' as const
  },
  
  CORS_ERROR: {
    title: 'Browser Security Restriction',
    message: 'Direct API calls are blocked by browser security (CORS policy).',
    action: 'Use OpenRouter as your AI provider for browser compatibility, or set up a proxy server.',
    documentation: '/docs/troubleshooting#cors-issues',
    severity: 'error' as const
  },

  // IOC Processing Errors
  INVALID_IOC_FORMAT: {
    title: 'Invalid IOC Format',
    message: 'The provided IOC doesn\'t match expected patterns for any supported type.',
    action: 'Check for typos, try defanging the IOC (replace . with [.]), or verify the IOC type.',
    severity: 'error' as const
  },
  
  IOC_EXTRACTION_FAILED: {
    title: 'IOC Extraction Failed',
    message: 'Unable to extract IOCs from the provided content.',
    action: 'Ensure the content contains valid IOCs, or try manual input if the format is unusual.',
    severity: 'error' as const
  },
  
  MALFORMED_INPUT: {
    title: 'Malformed Input Data',
    message: 'The input contains formatting issues that prevent processing.',
    action: 'Clean up the input text, remove special characters, or try a different format.',
    severity: 'error' as const
  },

  // Query Generation Errors
  QUERY_GENERATION_FAILED: {
    title: 'Query Generation Failed',
    message: 'Unable to generate a valid query for the selected SIEM platform.',
    action: 'Try a different hunt template, verify your IOC selection, or check the SIEM platform configuration.',
    documentation: '/docs/troubleshooting#query-generation',
    severity: 'error' as const
  },
  
  TEMPLATE_NOT_FOUND: {
    title: 'Hunt Template Not Found',
    message: 'The selected hunt template is not available or has been removed.',
    action: 'Select a different template from the available options or refresh the page.',
    severity: 'error' as const
  },
  
  VENDOR_NOT_SUPPORTED: {
    title: 'SIEM Platform Not Supported',
    message: 'The selected SIEM platform is not supported for this operation.',
    action: 'Choose from supported platforms: CrowdStrike, Splunk, Sentinel, Elastic, QRadar, or Chronicle.',
    severity: 'error' as const
  },

  // File Processing Errors
  FILE_TOO_LARGE: {
    title: 'File Size Limit Exceeded',
    message: 'The uploaded file exceeds the maximum size limit of 10MB.',
    action: 'Split large files into smaller chunks or use URL scanning for web content.',
    severity: 'error' as const
  },
  
  UNSUPPORTED_FILE_TYPE: {
    title: 'Unsupported File Type',
    message: 'This file type is not supported for IOC extraction.',
    action: 'Use supported formats: TXT, CSV, JSON, XML, or PDF files.',
    severity: 'error' as const
  },
  
  FILE_PROCESSING_FAILED: {
    title: 'File Processing Error',
    message: 'Unable to process the uploaded file due to corruption or encoding issues.',
    action: 'Verify the file is not corrupted, try saving in UTF-8 encoding, or use a different file.',
    severity: 'error' as const
  },

  // URL Scanning Errors
  URL_UNREACHABLE: {
    title: 'URL Unreachable',
    message: 'The specified URL cannot be accessed or does not exist.',
    action: 'Verify the URL is correct, check if it requires authentication, or try a different URL.',
    severity: 'error' as const
  },
  
  URL_BLOCKED: {
    title: 'URL Access Blocked',
    message: 'Access to this URL is blocked for security reasons.',
    action: 'This may be a private/internal URL or flagged as malicious. Use file upload instead.',
    severity: 'warning' as const
  },

  // Rule Generation Errors
  SIGMA_GENERATION_FAILED: {
    title: 'Sigma Rule Generation Failed',
    message: 'Unable to generate a valid Sigma rule from the provided IOCs.',
    action: 'Ensure you have sufficient IOCs of compatible types, or try adjusting the rule parameters.',
    severity: 'error' as const
  },
  
  YARA_GENERATION_FAILED: {
    title: 'YARA Rule Generation Failed',
    message: 'Unable to generate a valid YARA rule from the provided data.',
    action: 'Verify you have file hashes or samples, and ensure the IOC types are compatible with YARA.',
    severity: 'error' as const
  },

  // Authentication and Authorization
  AUTHENTICATION_REQUIRED: {
    title: 'Authentication Required',
    message: 'You need to sign in to access this feature.',
    action: 'Sign in to your account or create a new account to continue.',
    severity: 'info' as const
  },
  
  FEATURE_NOT_AVAILABLE: {
    title: 'Feature Not Available',
    message: 'This feature is not available in your current subscription tier.',
    action: 'Upgrade to Pro or Enterprise to access advanced features.',
    severity: 'info' as const
  },

  // Network and Connectivity
  NETWORK_ERROR: {
    title: 'Network Connection Error',
    message: 'Unable to connect to external services.',
    action: 'Check your internet connection and try again. Some features work offline.',
    severity: 'warning' as const
  },
  
  TIMEOUT_ERROR: {
    title: 'Request Timeout',
    message: 'The operation took too long and was cancelled.',
    action: 'Try with a smaller dataset, check your connection, or retry the operation.',
    severity: 'warning' as const
  },

  // Generic Fallbacks
  UNKNOWN_ERROR: {
    title: 'Unexpected Error',
    message: 'An unexpected error occurred during processing.',
    action: 'Please try again. If the problem persists, contact support with the error details.',
    documentation: '/docs/support',
    severity: 'error' as const
  }
};

export class ProfessionalErrorHandler {
  /**
   * Create a professional error from an error code
   */
  static createError(code: keyof typeof ERROR_CODES, context?: Record<string, any>): ProfessionalError {
    const errorTemplate = ERROR_CODES[code];
    if (!errorTemplate) {
      return {
        code: 'UNKNOWN_ERROR',
        ...ERROR_CODES.UNKNOWN_ERROR,
        context: { originalCode: code, ...context }
      };
    }

    return {
      code,
      ...errorTemplate,
      context
    };
  }

  /**
   * Handle and classify unknown errors
   */
  static handleUnknownError(error: any): ProfessionalError {
    // Network errors
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return this.createError('NETWORK_ERROR', { originalError: error.message });
    }

    // CORS errors
    if (error.message?.includes('CORS') || error.message?.includes('Cross-Origin')) {
      return this.createError('CORS_ERROR', { originalError: error.message });
    }

    // Timeout errors
    if (error.name === 'AbortError' || error.message?.includes('timeout')) {
      return this.createError('TIMEOUT_ERROR', { originalError: error.message });
    }

    // Rate limiting (common patterns)
    if (error.status === 429 || error.message?.includes('rate limit')) {
      return this.createError('API_RATE_LIMIT_EXCEEDED', { originalError: error.message });
    }

    // Authentication errors
    if (error.status === 401 || error.status === 403) {
      return this.createError('API_KEY_INVALID', { originalError: error.message });
    }

    // File size errors
    if (error.message?.includes('file size') || error.message?.includes('too large')) {
      return this.createError('FILE_TOO_LARGE', { originalError: error.message });
    }

    // Default fallback
    return this.createError('UNKNOWN_ERROR', { 
      originalError: error.message || error.toString(),
      stack: error.stack 
    });
  }

  /**
   * Format error for display in UI
   */
  static formatForUI(error: ProfessionalError) {
    return {
      title: error.title,
      description: error.message,
      action: error.action,
      variant: error.severity === 'critical' || error.severity === 'error' ? 'destructive' : 'default'
    };
  }

  /**
   * Log error for debugging (sanitized)
   */
  static logError(error: ProfessionalError, operation: string) {
    const logData = {
      timestamp: new Date().toISOString(),
      operation,
      code: error.code,
      severity: error.severity,
      context: error.context
    };

    if (error.severity === 'critical' || error.severity === 'error') {
      console.error('IntelForge Error:', logData);
    } else {
      console.warn('IntelForge Warning:', logData);
    }

    // In production, send to monitoring service
    if (process.env.NODE_ENV === 'production') {
      // analytics.trackError(logData);
    }
  }
}

export default ProfessionalErrorHandler;
