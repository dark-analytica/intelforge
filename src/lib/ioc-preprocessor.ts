/**
 * Professional IOC preprocessing for security practitioners
 * Handles defanged IOCs, noise reduction, and normalization
 */

export interface PreprocessingResult {
  processed: string;
  changes: string[];
  warnings: string[];
  confidence: number;
}

export class IOCPreprocessor {
  // Common defanging patterns used by security practitioners
  private static readonly DEFANGING_PATTERNS = {
    // URL schemes
    'hxxp://': 'http://',
    'hxxps://': 'https://',
    'h[t][t]p://': 'http://',
    'h[t][t]ps://': 'https://',
    'http[:]//': 'http://',
    'https[:]//': 'https://',
    
    // Domain separators
    '[.]': '.',
    '(.)': '.',
    '{.}': '.',
    '[dot]': '.',
    '(dot)': '.',
    ' dot ': '.',
    '_dot_': '.',
    
    // Email separators
    '[@]': '@',
    '(@)': '@',
    '{@}': '@',
    '[at]': '@',
    '(at)': '@',
    ' at ': '@',
    '_at_': '@',
    
    // Port separators
    '[:]': ':',
    '(:)': ':',
    '{:}': ':',
    
    // Path separators
    '[/]': '/',
    '(/)': '/',
    '{/}': '/'
  };

  // Common noise patterns to remove
  private static readonly NOISE_PATTERNS = [
    /^(IOC:|Indicator:|Hash:|Domain:|IP:|URL:|Email:)\s*/gim,
    /\s*\[DEFANGED\]\s*/gi,
    /\s*\[SANITIZED\]\s*/gi,
    /\s*\[REDACTED\]\s*/gi,
    /^\s*[-•*]\s*/gm, // Bullet points
    /^\s*\d+\.\s*/gm, // Numbered lists
    /\s*<[^>]*>\s*/g, // HTML tags
    /\s*\([^)]*defang[^)]*\)\s*/gi, // Defang notes
    /\s*\{[^}]*defang[^}]*\}\s*/gi,
    /\s*\[[^\]]*defang[^\]]*\]\s*/gi
  ];

  // Patterns that indicate potential false positives
  private static readonly FALSE_POSITIVE_INDICATORS = [
    /example\.(com|org|net)/i,
    /test\.(com|org|net)/i,
    /localhost/i,
    /127\.0\.0\.1/,
    /192\.168\./,
    /10\.\d+\.\d+\.\d+/,
    /172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/,
    /@(gmail|yahoo|hotmail|outlook)\.(com|net)/i,
    /\.(jpg|jpeg|png|gif|pdf|doc|docx|txt)$/i
  ];

  /**
   * Preprocess IOC input for better extraction
   */
  static preprocessIOCs(input: string): PreprocessingResult {
    const changes: string[] = [];
    const warnings: string[] = [];
    let processed = input.trim();
    let confidence = 1.0;

    if (!processed) {
      return {
        processed: '',
        changes: [],
        warnings: ['Empty input provided'],
        confidence: 0
      };
    }

    // Step 1: Apply defanging corrections
    let defangingApplied = false;
    Object.entries(this.DEFANGING_PATTERNS).forEach(([pattern, replacement]) => {
      const regex = new RegExp(pattern, 'gi');
      if (regex.test(processed)) {
        processed = processed.replace(regex, replacement);
        defangingApplied = true;
      }
    });

    if (defangingApplied) {
      changes.push('Applied defanging corrections');
    }

    // Step 2: Remove common noise patterns
    let noiseRemoved = false;
    this.NOISE_PATTERNS.forEach(pattern => {
      if (pattern.test(processed)) {
        processed = processed.replace(pattern, '');
        noiseRemoved = true;
      }
    });

    if (noiseRemoved) {
      changes.push('Removed noise and formatting artifacts');
    }

    // Step 3: Normalize whitespace and line breaks
    const originalLength = processed.length;
    processed = processed
      .replace(/\r\n/g, '\n') // Normalize line endings
      .replace(/\s+/g, ' ') // Collapse multiple spaces
      .replace(/\n\s*\n/g, '\n') // Remove empty lines
      .trim();

    if (processed.length !== originalLength) {
      changes.push('Normalized whitespace and formatting');
    }

    // Step 4: Check for potential false positives
    this.FALSE_POSITIVE_INDICATORS.forEach(pattern => {
      if (pattern.test(processed)) {
        warnings.push(`Potential false positive detected: ${pattern.source}`);
        confidence *= 0.8; // Reduce confidence
      }
    });

    // Step 5: Validate the result has extractable content
    if (processed.length < 3) {
      warnings.push('Processed input is very short, may not contain valid IOCs');
      confidence *= 0.5;
    }

    // Step 6: Check for common encoding issues
    if (processed.includes('\\x') || processed.includes('%')) {
      warnings.push('Input may contain URL or hex encoding that needs manual review');
      confidence *= 0.9;
    }

    return {
      processed,
      changes,
      warnings,
      confidence: Math.max(0, Math.min(1, confidence))
    };
  }

  /**
   * Preprocess specific IOC types with specialized handling
   */
  static preprocessByType(input: string, type: 'ip' | 'domain' | 'url' | 'email' | 'hash'): PreprocessingResult {
    const baseResult = this.preprocessIOCs(input);
    let processed = baseResult.processed;
    const changes = [...baseResult.changes];
    const warnings = [...baseResult.warnings];

    switch (type) {
      case 'ip':
        // Handle IP-specific defanging
        processed = processed.replace(/\[(\d+)\]/g, '$1');
        if (processed !== baseResult.processed) {
          changes.push('Applied IP-specific defanging');
        }
        break;

      case 'domain':
        // Handle domain-specific patterns
        processed = processed
          .replace(/\s+/g, '') // Remove all spaces from domains
          .toLowerCase(); // Normalize case
        if (processed !== baseResult.processed) {
          changes.push('Applied domain normalization');
        }
        break;

      case 'url':
        // Handle URL-specific patterns
        processed = processed.replace(/\s+/g, ''); // Remove spaces from URLs
        if (!processed.match(/^https?:\/\//)) {
          processed = 'http://' + processed;
          changes.push('Added missing protocol');
        }
        break;

      case 'email':
        // Handle email-specific patterns
        processed = processed
          .replace(/\s+/g, '') // Remove spaces
          .toLowerCase(); // Normalize case
        if (processed !== baseResult.processed) {
          changes.push('Applied email normalization');
        }
        break;

      case 'hash':
        // Handle hash-specific patterns
        processed = processed
          .replace(/\s+/g, '') // Remove all spaces
          .replace(/[:-]/g, '') // Remove separators
          .toLowerCase(); // Normalize case
        if (processed !== baseResult.processed) {
          changes.push('Applied hash normalization');
        }
        break;
    }

    return {
      processed,
      changes,
      warnings,
      confidence: baseResult.confidence
    };
  }

  /**
   * Batch preprocess multiple IOCs
   */
  static preprocessBatch(inputs: string[]): PreprocessingResult[] {
    return inputs.map(input => this.preprocessIOCs(input));
  }

  /**
   * Extract and preprocess IOCs from mixed content
   */
  static preprocessMixedContent(content: string): {
    lines: PreprocessingResult[];
    summary: {
      totalLines: number;
      processedLines: number;
      totalChanges: number;
      totalWarnings: number;
      averageConfidence: number;
    };
  } {
    const lines = content.split('\n').filter(line => line.trim());
    const results = lines.map(line => this.preprocessIOCs(line));
    
    const summary = {
      totalLines: lines.length,
      processedLines: results.filter(r => r.processed.length > 0).length,
      totalChanges: results.reduce((sum, r) => sum + r.changes.length, 0),
      totalWarnings: results.reduce((sum, r) => sum + r.warnings.length, 0),
      averageConfidence: results.length > 0 
        ? results.reduce((sum, r) => sum + r.confidence, 0) / results.length 
        : 0
    };

    return { lines: results, summary };
  }

  /**
   * Generate preprocessing report for user feedback
   */
  static generateReport(result: PreprocessingResult): string {
    const parts = [];
    
    if (result.changes.length > 0) {
      parts.push(`✅ Applied ${result.changes.length} improvement(s):`);
      result.changes.forEach(change => parts.push(`  • ${change}`));
    }
    
    if (result.warnings.length > 0) {
      parts.push(`⚠️  ${result.warnings.length} warning(s):`);
      result.warnings.forEach(warning => parts.push(`  • ${warning}`));
    }
    
    const confidenceLevel = result.confidence >= 0.9 ? 'High' : 
                           result.confidence >= 0.7 ? 'Medium' : 'Low';
    parts.push(`📊 Processing confidence: ${confidenceLevel} (${Math.round(result.confidence * 100)}%)`);
    
    return parts.join('\n');
  }
}

export default IOCPreprocessor;
