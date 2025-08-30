/**
 * Input validation and sanitization utilities
 */

import DOMPurify from 'isomorphic-dompurify';

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  sanitized?: string;
}

export class InputValidator {
  // IOC validation patterns
  private static readonly IOC_PATTERNS = {
    ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
    url: /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$/,
    email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    hash: {
      md5: /^[a-fA-F0-9]{32}$/,
      sha1: /^[a-fA-F0-9]{40}$/,
      sha256: /^[a-fA-F0-9]{64}$/,
      sha512: /^[a-fA-F0-9]{128}$/
    }
  };

  // File upload constraints
  private static readonly FILE_CONSTRAINTS = {
    maxSize: 10 * 1024 * 1024, // 10MB
    allowedTypes: [
      'text/plain',
      'text/csv',
      'application/json',
      'application/xml',
      'text/xml',
      'application/pdf'
    ],
    maxFiles: 5
  };

  /**
   * Validate and sanitize text input
   */
  static validateText(input: string, maxLength: number = 10000): ValidationResult {
    const errors: string[] = [];

    if (!input || typeof input !== 'string') {
      errors.push('Input must be a non-empty string');
      return { isValid: false, errors };
    }

    if (input.length > maxLength) {
      errors.push(`Input exceeds maximum length of ${maxLength} characters`);
    }

    // Check for potentially malicious patterns
    const maliciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /data:text\/html/gi,
      /vbscript:/gi
    ];

    for (const pattern of maliciousPatterns) {
      if (pattern.test(input)) {
        errors.push('Input contains potentially malicious content');
        break;
      }
    }

    // Sanitize the input
    const sanitized = DOMPurify.sanitize(input, {
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
      KEEP_CONTENT: true
    });

    return {
      isValid: errors.length === 0,
      errors,
      sanitized
    };
  }

  /**
   * Validate IOC format
   */
  static validateIOC(ioc: string, type?: string): ValidationResult {
    const errors: string[] = [];
    const trimmed = ioc.trim();

    if (!trimmed) {
      errors.push('IOC cannot be empty');
      return { isValid: false, errors };
    }

    // Auto-detect IOC type if not provided
    if (!type) {
      type = this.detectIOCType(trimmed);
    }

    switch (type) {
      case 'ip':
        if (!this.IOC_PATTERNS.ip.test(trimmed)) {
          errors.push('Invalid IP address format');
        }
        break;
      case 'domain':
        if (!this.IOC_PATTERNS.domain.test(trimmed)) {
          errors.push('Invalid domain format');
        }
        break;
      case 'url':
        if (!this.IOC_PATTERNS.url.test(trimmed)) {
          errors.push('Invalid URL format');
        }
        break;
      case 'email':
        if (!this.IOC_PATTERNS.email.test(trimmed)) {
          errors.push('Invalid email format');
        }
        break;
      case 'hash':
        if (!this.validateHash(trimmed)) {
          errors.push('Invalid hash format');
        }
        break;
      default:
        errors.push(`Unsupported IOC type: ${type}`);
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitized: trimmed
    };
  }

  /**
   * Validate file upload
   */
  static validateFile(file: File): ValidationResult {
    const errors: string[] = [];

    if (!file) {
      errors.push('No file provided');
      return { isValid: false, errors };
    }

    // Check file size
    if (file.size > this.FILE_CONSTRAINTS.maxSize) {
      errors.push(`File size exceeds ${this.FILE_CONSTRAINTS.maxSize / (1024 * 1024)}MB limit`);
    }

    // Check file type
    if (!this.FILE_CONSTRAINTS.allowedTypes.includes(file.type)) {
      errors.push(`File type ${file.type} not allowed`);
    }

    // Check filename for malicious patterns
    const filename = file.name;
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      errors.push('Invalid filename');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate multiple files
   */
  static validateFiles(files: FileList | File[]): ValidationResult {
    const errors: string[] = [];

    if (!files || files.length === 0) {
      errors.push('No files provided');
      return { isValid: false, errors };
    }

    if (files.length > this.FILE_CONSTRAINTS.maxFiles) {
      errors.push(`Too many files. Maximum ${this.FILE_CONSTRAINTS.maxFiles} allowed`);
    }

    // Validate each file
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const fileValidation = this.validateFile(file);
      if (!fileValidation.isValid) {
        errors.push(`File ${i + 1}: ${fileValidation.errors.join(', ')}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate URL for scanning
   */
  static validateURL(url: string): ValidationResult {
    const errors: string[] = [];

    if (!url || typeof url !== 'string') {
      errors.push('URL must be a non-empty string');
      return { isValid: false, errors };
    }

    const trimmed = url.trim();

    // Basic URL format validation
    if (!this.IOC_PATTERNS.url.test(trimmed)) {
      errors.push('Invalid URL format');
    }

    // Check for potentially dangerous URLs
    const dangerousPatterns = [
      /localhost/i,
      /127\.0\.0\.1/,
      /192\.168\./,
      /10\./,
      /172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /file:\/\//i,
      /ftp:\/\//i
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(trimmed)) {
        errors.push('URL points to potentially dangerous or internal resource');
        break;
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitized: trimmed
    };
  }

  /**
   * Validate API key format
   */
  static validateAPIKey(key: string, provider: string): ValidationResult {
    const errors: string[] = [];

    if (!key || typeof key !== 'string') {
      errors.push('API key must be a non-empty string');
      return { isValid: false, errors };
    }

    const trimmed = key.trim();

    // Provider-specific validation
    switch (provider.toLowerCase()) {
      case 'openai':
        if (!trimmed.startsWith('sk-') || trimmed.length < 40) {
          errors.push('Invalid OpenAI API key format');
        }
        break;
      case 'anthropic':
        if (!trimmed.startsWith('sk-ant-') || trimmed.length < 40) {
          errors.push('Invalid Anthropic API key format');
        }
        break;
      case 'google':
        if (trimmed.length < 30) {
          errors.push('Invalid Google API key format');
        }
        break;
      default:
        if (trimmed.length < 20) {
          errors.push('API key appears too short');
        }
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitized: trimmed
    };
  }

  /**
   * Detect IOC type from string
   */
  private static detectIOCType(ioc: string): string {
    if (this.IOC_PATTERNS.ip.test(ioc)) return 'ip';
    if (this.IOC_PATTERNS.email.test(ioc)) return 'email';
    if (this.IOC_PATTERNS.url.test(ioc)) return 'url';
    if (this.validateHash(ioc)) return 'hash';
    if (this.IOC_PATTERNS.domain.test(ioc)) return 'domain';
    return 'unknown';
  }

  /**
   * Validate hash format
   */
  private static validateHash(hash: string): boolean {
    return (
      this.IOC_PATTERNS.hash.md5.test(hash) ||
      this.IOC_PATTERNS.hash.sha1.test(hash) ||
      this.IOC_PATTERNS.hash.sha256.test(hash) ||
      this.IOC_PATTERNS.hash.sha512.test(hash)
    );
  }

  /**
   * Sanitize query parameters
   */
  static sanitizeQueryParams(params: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};

    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string') {
        sanitized[key] = DOMPurify.sanitize(value, {
          ALLOWED_TAGS: [],
          ALLOWED_ATTR: [],
          KEEP_CONTENT: true
        });
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        sanitized[key] = value;
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(item => 
          typeof item === 'string' ? DOMPurify.sanitize(item, {
            ALLOWED_TAGS: [],
            ALLOWED_ATTR: [],
            KEEP_CONTENT: true
          }) : item
        );
      }
    }

    return sanitized;
  }

  /**
   * Rate limiting check (client-side)
   */
  static checkRateLimit(key: string, maxRequests: number = 100, windowMs: number = 60000): boolean {
    const now = Date.now();
    const windowKey = `rate_limit_${key}_${Math.floor(now / windowMs)}`;
    
    const current = parseInt(localStorage.getItem(windowKey) || '0');
    if (current >= maxRequests) {
      return false;
    }

    localStorage.setItem(windowKey, (current + 1).toString());
    
    // Clean up old entries
    for (let i = 0; i < localStorage.length; i++) {
      const storageKey = localStorage.key(i);
      if (storageKey?.startsWith('rate_limit_')) {
        const timestamp = parseInt(storageKey.split('_')[3]);
        if (now - timestamp * windowMs > windowMs * 2) {
          localStorage.removeItem(storageKey);
        }
      }
    }

    return true;
  }
}

export default InputValidator;
