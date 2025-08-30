/**
 * CQL Performance Analysis and Optimization Engine
 * Analyzes CQL queries for performance issues and provides optimization suggestions
 */

export interface CQLAnalysisResult {
  query: string;
  performanceScore: number; // 0-100
  issues: PerformanceIssue[];
  optimizations: OptimizationSuggestion[];
  estimatedImpact: 'low' | 'medium' | 'high';
  complexity: 'simple' | 'moderate' | 'complex' | 'very_complex';
}

export interface PerformanceIssue {
  type: 'index_missing' | 'wildcard_leading' | 'function_in_where' | 'cartesian_product' | 
        'large_in_clause' | 'regex_performance' | 'subquery_inefficient' | 'missing_limit';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  location: string;
  impact: string;
}

export interface OptimizationSuggestion {
  type: 'add_index' | 'rewrite_condition' | 'add_limit' | 'optimize_join' | 
        'batch_operations' | 'use_exists' | 'partition_pruning';
  priority: 'low' | 'medium' | 'high';
  description: string;
  before: string;
  after: string;
  expectedImprovement: string;
}

export class CQLAnalyzer {
  private readonly PERFORMANCE_PATTERNS = {
    // Anti-patterns that hurt performance
    LEADING_WILDCARD: /LIKE\s+['"]%[^%]+/gi,
    FUNCTION_IN_WHERE: /WHERE\s+[^=<>]*\([^)]*\)\s*[=<>]/gi,
    LARGE_IN_CLAUSE: /IN\s*\([^)]{200,}\)/gi,
    MISSING_LIMIT: /SELECT\s+(?!.*LIMIT)/gi,
    CARTESIAN_JOIN: /FROM\s+\w+\s*,\s*\w+(?!\s+WHERE)/gi,
    REGEX_HEAVY: /REGEXP?[_\s]+/gi,
    SUBQUERY_IN_SELECT: /SELECT[^FROM]*\(SELECT[^)]*\)/gi,
    INEFFICIENT_OR: /OR\s+\w+\s*=\s*['"][^'"]*['"](\s+OR\s+\w+\s*=\s*['"][^'"]*['"]){3,}/gi
  };

  private readonly OPTIMIZATION_RULES = {
    // Common optimization patterns
    IN_TO_EXISTS: {
      pattern: /WHERE\s+(\w+)\s+IN\s*\(\s*SELECT\s+[^)]+\)/gi,
      suggestion: 'Replace IN subquery with EXISTS for better performance'
    },
    LIMIT_LARGE_RESULTS: {
      pattern: /SELECT\s+(?!.*LIMIT).*FROM/gi,
      suggestion: 'Add LIMIT clause to prevent large result sets'
    },
    INDEX_HINTS: {
      pattern: /WHERE\s+(\w+)\s*[=<>]/gi,
      suggestion: 'Consider adding index on frequently filtered columns'
    }
  };

  analyzeQuery(query: string): CQLAnalysisResult {
    const normalizedQuery = this.normalizeQuery(query);
    const issues = this.detectPerformanceIssues(normalizedQuery);
    const optimizations = this.generateOptimizations(normalizedQuery, issues);
    const complexity = this.assessComplexity(normalizedQuery);
    const performanceScore = this.calculatePerformanceScore(issues, complexity);
    const estimatedImpact = this.estimateImpact(issues);

    return {
      query,
      performanceScore,
      issues,
      optimizations,
      estimatedImpact,
      complexity
    };
  }

  analyzeBatch(queries: string[]): CQLAnalysisResult[] {
    return queries.map(query => this.analyzeQuery(query));
  }

  private normalizeQuery(query: string): string {
    return query
      .replace(/\s+/g, ' ')
      .replace(/\n/g, ' ')
      .trim()
      .toUpperCase();
  }

  private detectPerformanceIssues(query: string): PerformanceIssue[] {
    const issues: PerformanceIssue[] = [];

    // Check for leading wildcards
    if (this.PERFORMANCE_PATTERNS.LEADING_WILDCARD.test(query)) {
      issues.push({
        type: 'wildcard_leading',
        severity: 'high',
        description: 'Leading wildcard in LIKE clause prevents index usage',
        location: 'WHERE clause',
        impact: 'Forces full table scan, significantly slower on large datasets'
      });
    }

    // Check for functions in WHERE clause
    if (this.PERFORMANCE_PATTERNS.FUNCTION_IN_WHERE.test(query)) {
      issues.push({
        type: 'function_in_where',
        severity: 'medium',
        description: 'Function calls in WHERE clause prevent index optimization',
        location: 'WHERE clause',
        impact: 'May prevent efficient index usage'
      });
    }

    // Check for large IN clauses
    const inMatches = query.match(this.PERFORMANCE_PATTERNS.LARGE_IN_CLAUSE);
    if (inMatches) {
      issues.push({
        type: 'large_in_clause',
        severity: 'medium',
        description: `Large IN clause with ${inMatches[0].split(',').length} values`,
        location: 'WHERE clause',
        impact: 'Consider batching or using temporary tables for large value lists'
      });
    }

    // Check for missing LIMIT
    if (this.PERFORMANCE_PATTERNS.MISSING_LIMIT.test(query) && !query.includes('COUNT')) {
      issues.push({
        type: 'missing_limit',
        severity: 'medium',
        description: 'Query lacks LIMIT clause',
        location: 'Query structure',
        impact: 'May return unexpectedly large result sets'
      });
    }

    // Check for potential cartesian products
    if (this.PERFORMANCE_PATTERNS.CARTESIAN_JOIN.test(query)) {
      issues.push({
        type: 'cartesian_product',
        severity: 'critical',
        description: 'Potential cartesian product detected',
        location: 'FROM clause',
        impact: 'Can cause exponential performance degradation'
      });
    }

    // Check for regex usage
    if (this.PERFORMANCE_PATTERNS.REGEX_HEAVY.test(query)) {
      issues.push({
        type: 'regex_performance',
        severity: 'medium',
        description: 'Regular expressions can be performance intensive',
        location: 'WHERE clause',
        impact: 'Consider simpler string matching when possible'
      });
    }

    // Check for subqueries in SELECT
    if (this.PERFORMANCE_PATTERNS.SUBQUERY_IN_SELECT.test(query)) {
      issues.push({
        type: 'subquery_inefficient',
        severity: 'medium',
        description: 'Subquery in SELECT clause may execute for each row',
        location: 'SELECT clause',
        impact: 'Consider JOINs or CTEs for better performance'
      });
    }

    return issues;
  }

  private generateOptimizations(query: string, issues: PerformanceIssue[]): OptimizationSuggestion[] {
    const optimizations: OptimizationSuggestion[] = [];

    // Generate optimizations based on detected issues
    issues.forEach(issue => {
      switch (issue.type) {
        case 'wildcard_leading':
          optimizations.push({
            type: 'rewrite_condition',
            priority: 'high',
            description: 'Replace leading wildcard with suffix search or full-text search',
            before: "LIKE '%pattern'",
            after: "Use suffix index or full-text search capabilities",
            expectedImprovement: '10-100x faster on large datasets'
          });
          break;

        case 'large_in_clause':
          optimizations.push({
            type: 'batch_operations',
            priority: 'medium',
            description: 'Break large IN clause into smaller batches or use temporary table',
            before: 'WHERE column IN (value1, value2, ... value1000)',
            after: 'WHERE column IN (batch1) OR column IN (batch2) OR use temp table JOIN',
            expectedImprovement: 'Reduces memory usage and improves query plan'
          });
          break;

        case 'missing_limit':
          optimizations.push({
            type: 'add_limit',
            priority: 'medium',
            description: 'Add LIMIT clause to control result set size',
            before: 'SELECT * FROM events WHERE ...',
            after: 'SELECT * FROM events WHERE ... LIMIT 1000',
            expectedImprovement: 'Prevents memory issues and improves response time'
          });
          break;

        case 'cartesian_product':
          optimizations.push({
            type: 'optimize_join',
            priority: 'high',
            description: 'Add proper JOIN conditions to prevent cartesian product',
            before: 'FROM table1, table2',
            after: 'FROM table1 JOIN table2 ON table1.id = table2.foreign_id',
            expectedImprovement: 'Prevents exponential result growth'
          });
          break;

        case 'subquery_inefficient':
          optimizations.push({
            type: 'use_exists',
            priority: 'medium',
            description: 'Replace correlated subquery with JOIN or EXISTS',
            before: 'SELECT (SELECT ... FROM table2 WHERE ...) FROM table1',
            after: 'SELECT ... FROM table1 LEFT JOIN table2 ON ...',
            expectedImprovement: 'Reduces query execution time significantly'
          });
          break;
      }
    });

    // Add general optimizations
    if (!query.includes('INDEX') && query.includes('WHERE')) {
      optimizations.push({
        type: 'add_index',
        priority: 'medium',
        description: 'Consider adding indexes on frequently filtered columns',
        before: 'No specific indexes mentioned',
        after: 'CREATE INDEX idx_column ON table(column)',
        expectedImprovement: 'Dramatically improves WHERE clause performance'
      });
    }

    return optimizations;
  }

  private assessComplexity(query: string): 'simple' | 'moderate' | 'complex' | 'very_complex' {
    let complexityScore = 0;

    // Count complexity indicators
    const joinCount = (query.match(/JOIN/gi) || []).length;
    const subqueryCount = (query.match(/\(SELECT/gi) || []).length;
    const unionCount = (query.match(/UNION/gi) || []).length;
    const cteCount = (query.match(/WITH/gi) || []).length;
    const aggregateCount = (query.match(/(COUNT|SUM|AVG|MAX|MIN|GROUP BY)/gi) || []).length;

    complexityScore += joinCount * 2;
    complexityScore += subqueryCount * 3;
    complexityScore += unionCount * 2;
    complexityScore += cteCount * 1;
    complexityScore += aggregateCount * 1;

    if (complexityScore <= 2) return 'simple';
    if (complexityScore <= 6) return 'moderate';
    if (complexityScore <= 12) return 'complex';
    return 'very_complex';
  }

  private calculatePerformanceScore(issues: PerformanceIssue[], complexity: string): number {
    let score = 100;

    // Deduct points for issues
    issues.forEach(issue => {
      switch (issue.severity) {
        case 'critical': score -= 30; break;
        case 'high': score -= 20; break;
        case 'medium': score -= 10; break;
        case 'low': score -= 5; break;
      }
    });

    // Deduct points for complexity
    switch (complexity) {
      case 'very_complex': score -= 15; break;
      case 'complex': score -= 10; break;
      case 'moderate': score -= 5; break;
    }

    return Math.max(0, score);
  }

  private estimateImpact(issues: PerformanceIssue[]): 'low' | 'medium' | 'high' {
    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;
    const mediumIssues = issues.filter(i => i.severity === 'medium').length;

    if (criticalIssues > 0 || highIssues > 2) return 'high';
    if (highIssues > 0 || mediumIssues > 3) return 'medium';
    return 'low';
  }

  // Utility method to generate performance report
  generateReport(results: CQLAnalysisResult[]): string {
    const totalQueries = results.length;
    const avgScore = results.reduce((sum, r) => sum + r.performanceScore, 0) / totalQueries;
    const highImpactQueries = results.filter(r => r.estimatedImpact === 'high').length;
    const complexQueries = results.filter(r => r.complexity === 'complex' || r.complexity === 'very_complex').length;

    return `
CQL Performance Analysis Report
==============================

Summary:
- Total Queries Analyzed: ${totalQueries}
- Average Performance Score: ${avgScore.toFixed(1)}/100
- High Impact Issues: ${highImpactQueries} queries
- Complex Queries: ${complexQueries} queries

Top Recommendations:
${this.getTopRecommendations(results)}

Detailed Analysis:
${results.map((r, i) => this.formatQueryAnalysis(r, i + 1)).join('\n\n')}
    `.trim();
  }

  private getTopRecommendations(results: CQLAnalysisResult[]): string {
    const allOptimizations = results.flatMap(r => r.optimizations);
    const highPriorityOpts = allOptimizations.filter(o => o.priority === 'high');
    
    return highPriorityOpts
      .slice(0, 5)
      .map((opt, i) => `${i + 1}. ${opt.description}`)
      .join('\n');
  }

  private formatQueryAnalysis(result: CQLAnalysisResult, index: number): string {
    return `
Query ${index}: Performance Score ${result.performanceScore}/100
Complexity: ${result.complexity}
Impact: ${result.estimatedImpact}

Issues Found:
${result.issues.map(issue => `- ${issue.description} (${issue.severity})`).join('\n')}

Optimizations:
${result.optimizations.map(opt => `- ${opt.description}`).join('\n')}
    `.trim();
  }
}

// Export singleton instance
export const cqlAnalyzer = new CQLAnalyzer();
