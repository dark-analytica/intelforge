import { queryValidator, type QueryValidationResult } from './query-validator';
import { getVendorById } from './vendors';

export interface OptimizationSuggestion {
  id: string;
  title: string;
  description: string;
  category: 'performance' | 'readability' | 'maintainability' | 'security';
  impact: 'high' | 'medium' | 'low';
  effort: 'low' | 'medium' | 'high';
  originalQuery: string;
  optimizedQuery: string;
  explanation: string;
  estimatedImprovement: string;
}

export interface OptimizationReport {
  originalQuery: string;
  vendorId: string;
  moduleId?: string;
  suggestions: OptimizationSuggestion[];
  overallScore: number;
  categories: {
    performance: number;
    readability: number;
    maintainability: number;
    security: number;
  };
  summary: string;
}

class QueryOptimizer {
  optimizeQuery(query: string, vendorId: string, moduleId?: string): OptimizationReport {
    const vendor = getVendorById(vendorId);
    if (!vendor) {
      throw new Error(`Unknown vendor: ${vendorId}`);
    }

    const validation = queryValidator.validateQuery(query, vendorId, moduleId);
    const suggestions: OptimizationSuggestion[] = [];

    // Generate vendor-specific optimizations
    switch (vendorId) {
      case 'splunk':
        suggestions.push(...this.optimizeSPL(query, validation));
        break;
      case 'sentinel':
        suggestions.push(...this.optimizeKQL(query, validation));
        break;
      case 'elastic':
        suggestions.push(...this.optimizeESQL(query, validation));
        break;
      case 'qradar':
        suggestions.push(...this.optimizeAQL(query, validation));
        break;
      case 'chronicle':
        suggestions.push(...this.optimizeUDM(query, validation));
        break;
      case 'crowdstrike':
      case 'logscale':
        suggestions.push(...this.optimizeCQL(query, validation));
        break;
    }

    // Add generic optimizations
    suggestions.push(...this.optimizeGeneric(query, validation));

    // Calculate scores
    const categories = this.calculateCategoryScores(suggestions);
    const overallScore = this.calculateOverallScore(categories);
    const summary = this.generateSummary(suggestions, overallScore);

    return {
      originalQuery: query,
      vendorId,
      moduleId,
      suggestions,
      overallScore,
      categories,
      summary
    };
  }

  private optimizeSPL(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Index optimization
    if (!query.includes('index=') && !query.includes('source=')) {
      suggestions.push({
        id: 'spl-index-optimization',
        title: 'Add Index Specification',
        description: 'Specify an index to dramatically improve search performance',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery: `index=your_index ${query}`,
        explanation: 'Adding an index specification allows Splunk to search only relevant data buckets, reducing search time by 70-90%.',
        estimatedImprovement: '70-90% faster search time'
      });
    }

    // Time range optimization
    if (!query.includes('earliest=') && !query.includes('latest=')) {
      const optimizedQuery = query.includes('|') 
        ? query.replace('|', 'earliest=-24h latest=now |')
        : `${query} earliest=-24h latest=now`;
      
      suggestions.push({
        id: 'spl-time-range',
        title: 'Add Time Range Constraints',
        description: 'Limit the search time window to improve performance',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Time range constraints prevent Splunk from searching all historical data, significantly reducing search time.',
        estimatedImprovement: '50-80% faster search time'
      });
    }

    // Field extraction optimization
    if (query.includes('| search ') && query.includes('|')) {
      const optimizedQuery = query.replace(/\|\s*search\s+/gi, '| where ');
      suggestions.push({
        id: 'spl-search-to-where',
        title: 'Replace search with where',
        description: 'Use | where instead of | search for better performance',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'The where command is more efficient than search when filtering already retrieved events.',
        estimatedImprovement: '20-30% faster processing'
      });
    }

    // Field selection optimization
    if (!query.includes('| fields ') && !query.includes('| table ')) {
      const optimizedQuery = `${query} | fields _time, host, source, your_required_fields`;
      suggestions.push({
        id: 'spl-field-selection',
        title: 'Limit Field Selection',
        description: 'Select only required fields to reduce data transfer',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Limiting fields reduces memory usage and network transfer, especially important for large result sets.',
        estimatedImprovement: '30-50% less memory usage'
      });
    }

    // Wildcard optimization
    if (query.match(/^\s*\*/)) {
      const optimizedQuery = query.replace(/^\s*\*/, 'index=* ');
      suggestions.push({
        id: 'spl-wildcard-optimization',
        title: 'Optimize Leading Wildcards',
        description: 'Avoid leading wildcards or add more specific search terms',
        category: 'performance',
        impact: 'high',
        effort: 'medium',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Leading wildcards prevent efficient index usage. Add specific terms or index constraints.',
        estimatedImprovement: '60-80% faster search time'
      });
    }

    return suggestions;
  }

  private optimizeKQL(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Time filter optimization
    if (!query.includes('TimeGenerated') && !query.includes('timestamp')) {
      const optimizedQuery = query.includes('|') 
        ? query.replace('|', '| where TimeGenerated > ago(24h) |')
        : `${query} | where TimeGenerated > ago(24h)`;
      
      suggestions.push({
        id: 'kql-time-filter',
        title: 'Add Time Filter',
        description: 'Add TimeGenerated filter to limit query scope',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Time filters are crucial in KQL to prevent scanning large amounts of historical data.',
        estimatedImprovement: '70-90% faster query execution'
      });
    }

    // Result limiting
    if (!query.includes('| take ') && !query.includes('| limit ')) {
      const optimizedQuery = `${query} | take 1000`;
      suggestions.push({
        id: 'kql-result-limit',
        title: 'Add Result Limit',
        description: 'Limit results to reduce query cost and improve performance',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Result limits prevent excessive data processing and reduce Azure costs.',
        estimatedImprovement: '40-60% cost reduction'
      });
    }

    // Project optimization
    if (!query.includes('| project ')) {
      const optimizedQuery = `${query} | project TimeGenerated, Computer, EventID, your_required_columns`;
      suggestions.push({
        id: 'kql-project-optimization',
        title: 'Add Column Projection',
        description: 'Select only required columns to improve performance',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Column projection reduces data transfer and processing overhead.',
        estimatedImprovement: '30-50% faster processing'
      });
    }

    // Join optimization
    if (query.includes('| join ')) {
      suggestions.push({
        id: 'kql-join-optimization',
        title: 'Optimize Join Operations',
        description: 'Consider using lookup or union instead of join for better performance',
        category: 'performance',
        impact: 'high',
        effort: 'high',
        originalQuery: query,
        optimizedQuery: query.replace('| join', '| lookup'), // Simplified example
        explanation: 'Joins can be expensive in KQL. Consider alternatives like lookup tables or union operations.',
        estimatedImprovement: '50-70% faster execution'
      });
    }

    return suggestions;
  }

  private optimizeESQL(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Index pattern optimization
    if (query.includes('FROM logs-*')) {
      const optimizedQuery = query.replace('FROM logs-*', 'FROM logs-security-*, logs-network-*');
      suggestions.push({
        id: 'esql-index-pattern',
        title: 'Optimize Index Patterns',
        description: 'Use specific index patterns instead of broad wildcards',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Specific index patterns reduce the amount of data ES|QL needs to scan.',
        estimatedImprovement: '60-80% faster query execution'
      });
    }

    // Field selection optimization
    if (!query.includes('| KEEP ') && !query.includes('| DROP ')) {
      const optimizedQuery = `${query} | KEEP @timestamp, host.name, event.action, your_required_fields`;
      suggestions.push({
        id: 'esql-field-selection',
        title: 'Add Field Selection',
        description: 'Use KEEP to select only required fields',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Field selection reduces memory usage and improves query performance.',
        estimatedImprovement: '30-50% less memory usage'
      });
    }

    // Aggregation optimization
    if (query.includes('| STATS ') && !query.includes('| WHERE ')) {
      const optimizedQuery = query.replace('| STATS', '| WHERE @timestamp > NOW() - INTERVAL 1 DAY | STATS');
      suggestions.push({
        id: 'esql-filter-before-aggregation',
        title: 'Filter Before Aggregation',
        description: 'Add WHERE clause before STATS to reduce aggregation scope',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Filtering data before aggregation significantly reduces processing overhead.',
        estimatedImprovement: '50-70% faster aggregation'
      });
    }

    return suggestions;
  }

  private optimizeAQL(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Time range optimization
    if (!query.includes('LAST ') && !query.includes('START ')) {
      const optimizedQuery = query.includes('WHERE') 
        ? query.replace('WHERE', 'WHERE LAST 24 HOURS AND')
        : `${query} LAST 24 HOURS`;
      
      suggestions.push({
        id: 'aql-time-range',
        title: 'Add Time Range',
        description: 'Specify time range to improve query performance',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Time ranges prevent QRadar from scanning all historical data.',
        estimatedImprovement: '70-90% faster query execution'
      });
    }

    // Category filtering
    if (!query.includes('category =')) {
      const optimizedQuery = query.includes('WHERE') 
        ? query.replace('WHERE', 'WHERE category IN (1,2,3,4,5,6) AND')
        : `${query} WHERE category IN (1,2,3,4,5,6)`;
      
      suggestions.push({
        id: 'aql-category-filter',
        title: 'Add Category Filter',
        description: 'Filter by event categories to reduce data scope',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Category filters help QRadar focus on relevant event types.',
        estimatedImprovement: '40-60% faster processing'
      });
    }

    // LIMIT optimization
    if (!query.includes('LIMIT ')) {
      const optimizedQuery = `${query} LIMIT 10000`;
      suggestions.push({
        id: 'aql-result-limit',
        title: 'Add Result Limit',
        description: 'Limit results to prevent excessive data retrieval',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Result limits prevent memory issues and improve response times.',
        estimatedImprovement: '30-50% faster response'
      });
    }

    return suggestions;
  }

  private optimizeUDM(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Event type filtering
    if (!query.includes('metadata.event_type')) {
      const optimizedQuery = `metadata.event_type = "NETWORK_HTTP" AND ${query}`;
      suggestions.push({
        id: 'udm-event-type',
        title: 'Add Event Type Filter',
        description: 'Specify event type to improve query performance',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Event type filters help Chronicle focus on relevant data categories.',
        estimatedImprovement: '60-80% faster query execution'
      });
    }

    // Time window optimization
    if (!query.includes('metadata.event_timestamp')) {
      const optimizedQuery = `metadata.event_timestamp.seconds > ${Math.floor(Date.now() / 1000) - 86400} AND ${query}`;
      suggestions.push({
        id: 'udm-time-filter',
        title: 'Add Time Filter',
        description: 'Add timestamp filter to limit query scope',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Time filters are essential for Chronicle query performance.',
        estimatedImprovement: '70-90% faster execution'
      });
    }

    return suggestions;
  }

  private optimizeCQL(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Repository filtering
    if (!query.includes('#type=')) {
      const optimizedQuery = `#type=proxy ${query}`;
      suggestions.push({
        id: 'cql-repo-filter',
        title: 'Add Repository Filter',
        description: 'Specify data repository to improve performance',
        category: 'performance',
        impact: 'high',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Repository filters help LogScale/CrowdStrike focus on relevant data sources.',
        estimatedImprovement: '60-80% faster query execution'
      });
    }

    // Time bucket optimization
    if (query.includes('| timechart(') && !query.includes('span=')) {
      const optimizedQuery = query.replace('| timechart(', '| timechart(span=1h, ');
      suggestions.push({
        id: 'cql-timechart-span',
        title: 'Optimize Timechart Span',
        description: 'Add appropriate span to timechart for better performance',
        category: 'performance',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Proper time spans reduce the number of buckets and improve visualization performance.',
        estimatedImprovement: '30-50% faster rendering'
      });
    }

    // Field selection optimization
    if (query.includes('| groupBy(') && !query.includes('function=')) {
      const optimizedQuery = query.replace('| groupBy(', '| groupBy(function=count(), ');
      suggestions.push({
        id: 'cql-groupby-function',
        title: 'Specify GroupBy Function',
        description: 'Add aggregation function to groupBy for clarity',
        category: 'readability',
        impact: 'low',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Explicit aggregation functions make queries more readable and maintainable.',
        estimatedImprovement: 'Better code clarity'
      });
    }

    return suggestions;
  }

  private optimizeGeneric(query: string, validation: QueryValidationResult): OptimizationSuggestion[] {
    const suggestions: OptimizationSuggestion[] = [];

    // Query length optimization
    if (query.length > 1000) {
      suggestions.push({
        id: 'generic-query-length',
        title: 'Consider Query Modularization',
        description: 'Break long queries into smaller, reusable components',
        category: 'maintainability',
        impact: 'medium',
        effort: 'high',
        originalQuery: query,
        optimizedQuery: '// Consider breaking this into multiple queries or functions',
        explanation: 'Long queries are harder to maintain, debug, and optimize. Consider modularization.',
        estimatedImprovement: 'Better maintainability'
      });
    }

    // Comment optimization
    if (!query.includes('//') && !query.includes('/*') && query.length > 200) {
      const optimizedQuery = `// Query purpose: Describe what this query does\n${query}`;
      suggestions.push({
        id: 'generic-add-comments',
        title: 'Add Query Documentation',
        description: 'Add comments to explain query purpose and logic',
        category: 'maintainability',
        impact: 'low',
        effort: 'low',
        originalQuery: query,
        optimizedQuery,
        explanation: 'Comments improve query maintainability and team collaboration.',
        estimatedImprovement: 'Better documentation'
      });
    }

    // Security considerations
    if (query.includes('*') && !query.includes('index=') && !query.includes('#type=')) {
      suggestions.push({
        id: 'generic-security-scope',
        title: 'Limit Query Scope for Security',
        description: 'Add data source constraints to prevent unauthorized data access',
        category: 'security',
        impact: 'medium',
        effort: 'low',
        originalQuery: query,
        optimizedQuery: 'Add appropriate data source filters',
        explanation: 'Broad queries may access sensitive data. Always scope queries appropriately.',
        estimatedImprovement: 'Better security posture'
      });
    }

    return suggestions;
  }

  private calculateCategoryScores(suggestions: OptimizationSuggestion[]): {
    performance: number;
    readability: number;
    maintainability: number;
    security: number;
  } {
    const categories = {
      performance: 0,
      readability: 0,
      maintainability: 0,
      security: 0
    };

    const counts = {
      performance: 0,
      readability: 0,
      maintainability: 0,
      security: 0
    };

    suggestions.forEach(suggestion => {
      const impactScore = suggestion.impact === 'high' ? 3 : suggestion.impact === 'medium' ? 2 : 1;
      categories[suggestion.category] += impactScore;
      counts[suggestion.category]++;
    });

    // Normalize scores (0-100)
    Object.keys(categories).forEach(category => {
      const key = category as keyof typeof categories;
      if (counts[key] > 0) {
        categories[key] = Math.min(100, (categories[key] / counts[key]) * 33.33);
      } else {
        categories[key] = 100; // No issues found
      }
    });

    return categories;
  }

  private calculateOverallScore(categories: {
    performance: number;
    readability: number;
    maintainability: number;
    security: number;
  }): number {
    // Weighted average (performance is most important)
    const weights = {
      performance: 0.4,
      readability: 0.2,
      maintainability: 0.2,
      security: 0.2
    };

    return Math.round(
      categories.performance * weights.performance +
      categories.readability * weights.readability +
      categories.maintainability * weights.maintainability +
      categories.security * weights.security
    );
  }

  private generateSummary(suggestions: OptimizationSuggestion[], overallScore: number): string {
    const highImpactCount = suggestions.filter(s => s.impact === 'high').length;
    const performanceCount = suggestions.filter(s => s.category === 'performance').length;
    
    if (overallScore >= 90) {
      return `Excellent query optimization! ${suggestions.length} minor improvements available.`;
    } else if (overallScore >= 70) {
      return `Good query with ${suggestions.length} optimization opportunities. ${highImpactCount} high-impact improvements available.`;
    } else if (overallScore >= 50) {
      return `Query needs optimization. ${performanceCount} performance improvements and ${highImpactCount} high-impact changes recommended.`;
    } else {
      return `Query requires significant optimization. ${highImpactCount} critical improvements needed for production use.`;
    }
  }
}

export const queryOptimizer = new QueryOptimizer();
