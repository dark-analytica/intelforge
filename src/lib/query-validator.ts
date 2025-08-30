import { vendors, getVendorById, getModuleById } from './vendors';

export interface QueryValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: QuerySuggestion[];
  performance: PerformanceAnalysis;
  syntax: SyntaxAnalysis;
}

export interface ValidationError {
  type: 'syntax' | 'field' | 'function' | 'logic';
  message: string;
  line?: number;
  column?: number;
  severity: 'error' | 'warning';
}

export interface ValidationWarning {
  type: 'performance' | 'best_practice' | 'compatibility';
  message: string;
  suggestion?: string;
}

export interface QuerySuggestion {
  type: 'optimization' | 'alternative' | 'enhancement';
  title: string;
  description: string;
  before?: string;
  after?: string;
  impact: 'high' | 'medium' | 'low';
}

export interface PerformanceAnalysis {
  estimatedComplexity: 'low' | 'medium' | 'high';
  indexUsage: 'optimal' | 'suboptimal' | 'poor';
  timeRangeOptimization: 'good' | 'moderate' | 'poor';
  fieldSelectionEfficiency: 'efficient' | 'moderate' | 'inefficient';
  recommendations: string[];
}

export interface SyntaxAnalysis {
  queryLanguage: string;
  detectedPatterns: string[];
  compatibilityIssues: string[];
  modernizationSuggestions: string[];
}

class QueryValidator {
  validateQuery(query: string, vendorId: string, moduleId?: string): QueryValidationResult {
    const vendor = getVendorById(vendorId);
    if (!vendor) {
      return this.createErrorResult('Invalid vendor ID');
    }

    const module = moduleId ? getModuleById(vendorId, moduleId) : vendor.modules[0];
    if (!module) {
      return this.createErrorResult('Invalid module ID');
    }

    const result: QueryValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      suggestions: [],
      performance: this.analyzePerformance(query, vendorId),
      syntax: this.analyzeSyntax(query, vendorId)
    };

    // Perform vendor-specific validation
    switch (vendorId) {
      case 'splunk':
        this.validateSPL(query, result);
        break;
      case 'sentinel':
        this.validateKQL(query, result);
        break;
      case 'elastic':
        this.validateESQL(query, result);
        break;
      case 'qradar':
        this.validateAQL(query, result);
        break;
      case 'chronicle':
        this.validateUDM(query, result);
        break;
      case 'crowdstrike':
      case 'logscale':
        this.validateCQL(query, result);
        break;
      default:
        this.validateGeneric(query, result);
    }

    // Validate field usage
    this.validateFieldUsage(query, module, result);

    // Add performance suggestions
    this.addPerformanceSuggestions(query, vendorId, result);

    // Check for common anti-patterns
    this.checkAntiPatterns(query, vendorId, result);

    result.isValid = result.errors.filter(e => e.severity === 'error').length === 0;
    return result;
  }

  private validateSPL(query: string, result: QueryValidationResult): void {
    // SPL-specific validation
    const splPatterns = {
      searchCommand: /^\s*search\s+/i,
      indexPattern: /index\s*=\s*[\w\*\-]+/i,
      sourcetypePattern: /sourcetype\s*=\s*[\w\*\-:]+/i,
      pipeCommands: /\|\s*(stats|eval|where|sort|head|tail|dedup|rex|table|fields)/gi
    };

    // Check for proper search command
    if (!splPatterns.searchCommand.test(query) && !splPatterns.indexPattern.test(query)) {
      result.warnings.push({
        type: 'best_practice',
        message: 'SPL queries should start with a search command or index specification',
        suggestion: 'Add "search" command or "index=" at the beginning'
      });
    }

    // Check for time range optimization
    if (!query.includes('earliest=') && !query.includes('latest=')) {
      result.warnings.push({
        type: 'performance',
        message: 'No time range specified - query may be slow',
        suggestion: 'Add earliest= and latest= time modifiers'
      });
    }

    // Check for inefficient wildcards
    if (query.includes('*') && query.indexOf('*') < 10) {
      result.warnings.push({
        type: 'performance',
        message: 'Leading wildcards can significantly impact performance',
        suggestion: 'Avoid wildcards at the beginning of search terms'
      });
    }

    // Validate pipe command syntax
    const pipes = query.match(splPatterns.pipeCommands) || [];
    pipes.forEach(pipe => {
      const command = pipe.replace('|', '').trim().split(' ')[0];
      this.validateSPLCommand(command, query, result);
    });
  }

  private validateKQL(query: string, result: QueryValidationResult): void {
    // KQL-specific validation
    const kqlPatterns = {
      tablePattern: /^\s*\w+\s*\|/,
      operators: /(where|project|summarize|order\s+by|take|extend|join)/gi,
      timeFilters: /(TimeGenerated|timestamp)\s*(>=|>|<=|<|==)/gi
    };

    // Check for proper table specification
    if (!kqlPatterns.tablePattern.test(query)) {
      result.errors.push({
        type: 'syntax',
        message: 'KQL queries must start with a table name',
        severity: 'error'
      });
    }

    // Check for time filtering
    if (!kqlPatterns.timeFilters.test(query)) {
      result.warnings.push({
        type: 'performance',
        message: 'No time filter detected - query may be slow',
        suggestion: 'Add TimeGenerated filter to limit time range'
      });
    }

    // Validate KQL operators
    const operators = query.match(kqlPatterns.operators) || [];
    operators.forEach(op => {
      this.validateKQLOperator(op.trim(), query, result);
    });
  }

  private validateESQL(query: string, result: QueryValidationResult): void {
    // ES|QL-specific validation
    if (!query.toUpperCase().includes('FROM ')) {
      result.errors.push({
        type: 'syntax',
        message: 'ES|QL queries must include a FROM clause',
        severity: 'error'
      });
    }

    // Check for proper ES|QL syntax
    const esqlKeywords = ['FROM', 'WHERE', 'STATS', 'SORT', 'LIMIT', 'KEEP', 'DROP'];
    const upperQuery = query.toUpperCase();
    
    esqlKeywords.forEach(keyword => {
      if (upperQuery.includes(`| ${keyword}`)) {
        result.warnings.push({
          type: 'syntax',
          message: `ES|QL uses ${keyword} without pipe prefix`,
          suggestion: `Use "${keyword}" instead of "| ${keyword}"`
        });
      }
    });
  }

  private validateAQL(query: string, result: QueryValidationResult): void {
    // AQL-specific validation
    if (!query.toUpperCase().includes('SELECT ')) {
      result.errors.push({
        type: 'syntax',
        message: 'AQL queries must include a SELECT statement',
        severity: 'error'
      });
    }

    // Check for proper time range
    if (!query.includes('LAST ') && !query.includes('START ')) {
      result.warnings.push({
        type: 'performance',
        message: 'No time range specified in AQL query',
        suggestion: 'Add LAST X HOURS or START/STOP time range'
      });
    }
  }

  private validateUDM(query: string, result: QueryValidationResult): void {
    // UDM-specific validation
    if (!query.includes('metadata.event_type')) {
      result.warnings.push({
        type: 'best_practice',
        message: 'UDM queries should specify event type for better performance',
        suggestion: 'Add metadata.event_type filter'
      });
    }

    // Check for proper UDM field syntax
    const udmFields = ['principal.', 'target.', 'metadata.', 'network.'];
    const hasUDMFields = udmFields.some(field => query.includes(field));
    
    if (!hasUDMFields) {
      result.warnings.push({
        type: 'compatibility',
        message: 'Query may not use proper UDM field structure',
        suggestion: 'Use UDM structured fields (principal.*, target.*, metadata.*)'
      });
    }
  }

  private validateCQL(query: string, result: QueryValidationResult): void {
    // CQL-specific validation
    const cqlPatterns = {
      repoFilter: /#type\s*=\s*\w+/i,
      timeFilter: /@timestamp/i,
      functions: /(groupBy|stats|sort|timechart|bucket)/gi
    };

    // Check for repository specification
    if (!cqlPatterns.repoFilter.test(query)) {
      result.warnings.push({
        type: 'performance',
        message: 'No repository filter specified',
        suggestion: 'Add #type= filter to improve query performance'
      });
    }

    // Validate CQL functions
    const functions = query.match(cqlPatterns.functions) || [];
    functions.forEach(func => {
      this.validateCQLFunction(func, query, result);
    });
  }

  private validateGeneric(query: string, result: QueryValidationResult): void {
    // Generic validation for unknown query languages
    if (query.trim().length === 0) {
      result.errors.push({
        type: 'syntax',
        message: 'Query cannot be empty',
        severity: 'error'
      });
    }

    if (query.length > 10000) {
      result.warnings.push({
        type: 'performance',
        message: 'Very long query may impact performance',
        suggestion: 'Consider breaking into smaller queries'
      });
    }
  }

  private validateFieldUsage(query: string, module: any, result: QueryValidationResult): void {
    const fieldMappings = module.fields || {};
    const usedFields = this.extractFieldNames(query);
    
    usedFields.forEach(field => {
      if (!fieldMappings[field] && !this.isCommonField(field)) {
        result.warnings.push({
          type: 'compatibility',
          message: `Field "${field}" not found in module field mappings`,
          suggestion: 'Verify field name or add to custom field mappings'
        });
      }
    });
  }

  private addPerformanceSuggestions(query: string, vendorId: string, result: QueryValidationResult): void {
    // Add vendor-specific performance suggestions
    if (vendorId === 'splunk') {
      if (query.includes('*') && !query.includes('index=')) {
        result.suggestions.push({
          type: 'optimization',
          title: 'Add index specification',
          description: 'Specifying an index can significantly improve search performance',
          impact: 'high'
        });
      }
    }

    if (vendorId === 'sentinel') {
      if (!query.includes('| take ') && !query.includes('| limit ')) {
        result.suggestions.push({
          type: 'optimization',
          title: 'Add result limit',
          description: 'Limiting results can improve query performance and reduce costs',
          impact: 'medium'
        });
      }
    }

    // Generic suggestions
    if (query.split('\n').length > 20) {
      result.suggestions.push({
        type: 'enhancement',
        title: 'Consider query modularization',
        description: 'Break complex queries into smaller, reusable components',
        impact: 'medium'
      });
    }
  }

  private checkAntiPatterns(query: string, vendorId: string, result: QueryValidationResult): void {
    // Check for common anti-patterns
    
    // Overly broad searches
    if (query.includes('*') && query.replace(/\s/g, '').length < 20) {
      result.warnings.push({
        type: 'performance',
        message: 'Very broad search pattern detected',
        suggestion: 'Add more specific search criteria to improve performance'
      });
    }

    // Nested subqueries (potential performance issue)
    const subqueryCount = (query.match(/\(/g) || []).length;
    if (subqueryCount > 3) {
      result.warnings.push({
        type: 'performance',
        message: 'Multiple nested subqueries detected',
        suggestion: 'Consider flattening the query structure'
      });
    }

    // Case sensitivity issues
    if (vendorId === 'splunk' && /[A-Z]/.test(query) && !query.includes('case(')) {
      result.warnings.push({
        type: 'best_practice',
        message: 'Mixed case in search terms - Splunk searches are case-sensitive',
        suggestion: 'Use consistent casing or case-insensitive functions'
      });
    }
  }

  private analyzePerformance(query: string, vendorId: string): PerformanceAnalysis {
    let complexity: 'low' | 'medium' | 'high' = 'low';
    let indexUsage: 'optimal' | 'suboptimal' | 'poor' = 'optimal';
    let timeRangeOptimization: 'good' | 'moderate' | 'poor' = 'good';
    let fieldSelectionEfficiency: 'efficient' | 'moderate' | 'inefficient' = 'efficient';
    const recommendations: string[] = [];

    // Analyze complexity
    const pipeCount = (query.match(/\|/g) || []).length;
    const joinCount = (query.match(/join/gi) || []).length;
    const subqueryCount = (query.match(/\(/g) || []).length;

    if (pipeCount > 5 || joinCount > 2 || subqueryCount > 3) {
      complexity = 'high';
      recommendations.push('Consider breaking complex query into multiple steps');
    } else if (pipeCount > 2 || joinCount > 0 || subqueryCount > 1) {
      complexity = 'medium';
    }

    // Analyze index usage
    if (vendorId === 'splunk' && !query.includes('index=')) {
      indexUsage = 'poor';
      recommendations.push('Specify index to improve search performance');
    } else if (query.includes('*') && query.indexOf('*') < 10) {
      indexUsage = 'suboptimal';
      recommendations.push('Avoid leading wildcards for better index utilization');
    }

    // Analyze time range
    const hasTimeFilter = query.includes('earliest=') || 
                         query.includes('TimeGenerated') || 
                         query.includes('@timestamp') ||
                         query.includes('LAST ');
    
    if (!hasTimeFilter) {
      timeRangeOptimization = 'poor';
      recommendations.push('Add time range filters to limit search scope');
    }

    // Analyze field selection
    if (query.includes('SELECT *') || (!query.includes('| fields ') && !query.includes('| project '))) {
      fieldSelectionEfficiency = 'moderate';
      recommendations.push('Select only required fields to reduce data transfer');
    }

    return {
      estimatedComplexity: complexity,
      indexUsage,
      timeRangeOptimization,
      fieldSelectionEfficiency,
      recommendations
    };
  }

  private analyzeSyntax(query: string, vendorId: string): SyntaxAnalysis {
    const detectedPatterns: string[] = [];
    const compatibilityIssues: string[] = [];
    const modernizationSuggestions: string[] = [];

    // Detect query patterns
    if (query.includes('| stats ')) detectedPatterns.push('Aggregation');
    if (query.includes('| where ')) detectedPatterns.push('Filtering');
    if (query.includes('| sort ')) detectedPatterns.push('Sorting');
    if (query.includes('| join ')) detectedPatterns.push('Joins');

    // Check for compatibility issues
    if (vendorId === 'splunk' && query.includes('| search ')) {
      compatibilityIssues.push('Redundant search command in pipe');
      modernizationSuggestions.push('Use | where instead of | search for better performance');
    }

    if (vendorId === 'sentinel' && query.includes('=~')) {
      modernizationSuggestions.push('Consider using contains() or has() for string matching');
    }

    return {
      queryLanguage: this.getQueryLanguage(vendorId),
      detectedPatterns,
      compatibilityIssues,
      modernizationSuggestions
    };
  }

  private validateSPLCommand(command: string, query: string, result: QueryValidationResult): void {
    const validSPLCommands = ['stats', 'eval', 'where', 'sort', 'head', 'tail', 'dedup', 'rex', 'table', 'fields'];
    
    if (!validSPLCommands.includes(command.toLowerCase())) {
      result.warnings.push({
        type: 'syntax',
        message: `Unknown or deprecated SPL command: ${command}`,
        suggestion: 'Verify command syntax or use alternative'
      });
    }
  }

  private validateKQLOperator(operator: string, query: string, result: QueryValidationResult): void {
    const validKQLOperators = ['where', 'project', 'summarize', 'order by', 'take', 'extend', 'join'];
    
    if (!validKQLOperators.includes(operator.toLowerCase())) {
      result.warnings.push({
        type: 'syntax',
        message: `Unknown KQL operator: ${operator}`,
        suggestion: 'Verify operator syntax'
      });
    }
  }

  private validateCQLFunction(func: string, query: string, result: QueryValidationResult): void {
    const validCQLFunctions = ['groupby', 'stats', 'sort', 'timechart', 'bucket'];
    
    if (!validCQLFunctions.includes(func.toLowerCase())) {
      result.warnings.push({
        type: 'syntax',
        message: `Unknown or deprecated CQL function: ${func}`,
        suggestion: 'Verify function syntax'
      });
    }
  }

  private extractFieldNames(query: string): string[] {
    // Simple field extraction - can be enhanced
    const fieldPattern = /\b([a-zA-Z_][a-zA-Z0-9_\.]*)\s*[=!<>]/g;
    const matches = query.match(fieldPattern) || [];
    return matches.map(match => match.replace(/\s*[=!<>].*/, ''));
  }

  private isCommonField(field: string): boolean {
    const commonFields = ['timestamp', 'time', '_time', 'TimeGenerated', '@timestamp', 'host', 'source', 'index'];
    return commonFields.includes(field);
  }

  private getQueryLanguage(vendorId: string): string {
    const languageMap: Record<string, string> = {
      'splunk': 'SPL',
      'sentinel': 'KQL',
      'elastic': 'ES|QL',
      'qradar': 'AQL',
      'chronicle': 'UDM Search',
      'crowdstrike': 'CQL',
      'logscale': 'CQL'
    };
    
    return languageMap[vendorId] || 'Unknown';
  }

  private createErrorResult(message: string): QueryValidationResult {
    return {
      isValid: false,
      errors: [{
        type: 'logic',
        message,
        severity: 'error'
      }],
      warnings: [],
      suggestions: [],
      performance: {
        estimatedComplexity: 'low',
        indexUsage: 'poor',
        timeRangeOptimization: 'poor',
        fieldSelectionEfficiency: 'inefficient',
        recommendations: []
      },
      syntax: {
        queryLanguage: 'Unknown',
        detectedPatterns: [],
        compatibilityIssues: [],
        modernizationSuggestions: []
      }
    };
  }
}

export const queryValidator = new QueryValidator();
