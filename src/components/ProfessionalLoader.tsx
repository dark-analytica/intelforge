/**
 * Professional loading component with multi-stage progress indication
 * Designed for enterprise security tools
 */

import React from 'react';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Loader2, CheckCircle2, AlertCircle, Clock } from 'lucide-react';

export interface LoadingStage {
  id: string;
  name: string;
  description: string;
  estimatedDuration?: number; // seconds
}

export interface LoadingState {
  currentStage: string;
  progress: number; // 0-100
  message: string;
  estimatedTimeRemaining?: number; // seconds
  stages: LoadingStage[];
  completedStages: string[];
  error?: string;
}

interface ProfessionalLoaderProps {
  state: LoadingState;
  className?: string;
  showStageList?: boolean;
  compact?: boolean;
}

export const ProfessionalLoader: React.FC<ProfessionalLoaderProps> = ({
  state,
  className = '',
  showStageList = true,
  compact = false
}) => {
  const currentStageIndex = state.stages.findIndex(s => s.id === state.currentStage);
  const currentStageInfo = state.stages[currentStageIndex];

  const formatTime = (seconds: number): string => {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.round(seconds % 60);
    return `${minutes}m ${remainingSeconds}s`;
  };

  if (compact) {
    return (
      <div className={`flex items-center space-x-3 ${className}`}>
        <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
        <div className="flex-1">
          <div className="text-sm font-medium">{state.message}</div>
          <Progress value={state.progress} className="h-1 mt-1" />
        </div>
        {state.estimatedTimeRemaining && (
          <Badge variant="secondary" className="text-xs">
            {formatTime(state.estimatedTimeRemaining)}
          </Badge>
        )}
      </div>
    );
  }

  return (
    <Card className={`w-full ${className}`}>
      <CardContent className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <Loader2 className="h-5 w-5 animate-spin text-blue-500" />
            <div>
              <h3 className="font-semibold text-lg">Processing</h3>
              <p className="text-sm text-muted-foreground">
                {currentStageInfo?.name || state.currentStage}
              </p>
            </div>
          </div>
          
          {state.estimatedTimeRemaining && (
            <div className="text-right">
              <div className="flex items-center space-x-1 text-sm text-muted-foreground">
                <Clock className="h-3 w-3" />
                <span>{formatTime(state.estimatedTimeRemaining)} remaining</span>
              </div>
            </div>
          )}
        </div>

        {/* Progress Bar */}
        <div className="space-y-2 mb-4">
          <div className="flex justify-between text-sm">
            <span>{state.message}</span>
            <span className="text-muted-foreground">{Math.round(state.progress)}%</span>
          </div>
          <Progress value={state.progress} className="h-2" />
        </div>

        {/* Stage List */}
        {showStageList && state.stages.length > 1 && (
          <div className="space-y-2">
            <h4 className="text-sm font-medium text-muted-foreground mb-3">Progress</h4>
            <div className="space-y-2">
              {state.stages.map((stage, index) => {
                const isCompleted = state.completedStages.includes(stage.id);
                const isCurrent = stage.id === state.currentStage;
                const isPending = !isCompleted && !isCurrent;

                return (
                  <div
                    key={stage.id}
                    className={`flex items-center space-x-3 p-2 rounded-md transition-colors ${
                      isCurrent ? 'bg-blue-50 border border-blue-200' :
                      isCompleted ? 'bg-green-50' :
                      'bg-gray-50'
                    }`}
                  >
                    <div className="flex-shrink-0">
                      {isCompleted ? (
                        <CheckCircle2 className="h-4 w-4 text-green-600" />
                      ) : isCurrent ? (
                        <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
                      ) : (
                        <div className="h-4 w-4 rounded-full border-2 border-gray-300" />
                      )}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className={`text-sm font-medium ${
                        isCurrent ? 'text-blue-900' :
                        isCompleted ? 'text-green-900' :
                        'text-gray-500'
                      }`}>
                        {stage.name}
                      </div>
                      <div className={`text-xs ${
                        isCurrent ? 'text-blue-700' :
                        isCompleted ? 'text-green-700' :
                        'text-gray-400'
                      }`}>
                        {stage.description}
                      </div>
                    </div>
                    
                    {stage.estimatedDuration && isPending && (
                      <Badge variant="outline" className="text-xs">
                        ~{formatTime(stage.estimatedDuration)}
                      </Badge>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Error State */}
        {state.error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <div className="flex items-center space-x-2">
              <AlertCircle className="h-4 w-4 text-red-600" />
              <span className="text-sm font-medium text-red-900">Error</span>
            </div>
            <p className="text-sm text-red-700 mt-1">{state.error}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

// Predefined stage configurations for common operations
export const LOADING_STAGES = {
  IOC_EXTRACTION: [
    {
      id: 'preprocessing',
      name: 'Preprocessing Input',
      description: 'Cleaning and normalizing input data',
      estimatedDuration: 2
    },
    {
      id: 'extraction',
      name: 'Extracting IOCs',
      description: 'Identifying indicators of compromise',
      estimatedDuration: 5
    },
    {
      id: 'validation',
      name: 'Validating Results',
      description: 'Checking IOC formats and removing false positives',
      estimatedDuration: 3
    }
  ],

  QUERY_GENERATION: [
    {
      id: 'template_selection',
      name: 'Selecting Template',
      description: 'Choosing optimal hunt template',
      estimatedDuration: 1
    },
    {
      id: 'query_building',
      name: 'Building Query',
      description: 'Generating SIEM-specific syntax',
      estimatedDuration: 3
    },
    {
      id: 'optimization',
      name: 'Optimizing Performance',
      description: 'Applying vendor-specific optimizations',
      estimatedDuration: 2
    },
    {
      id: 'validation',
      name: 'Validating Syntax',
      description: 'Checking query syntax and logic',
      estimatedDuration: 2
    }
  ],

  RULE_GENERATION: [
    {
      id: 'analysis',
      name: 'Analyzing IOCs',
      description: 'Grouping and categorizing indicators',
      estimatedDuration: 3
    },
    {
      id: 'rule_creation',
      name: 'Creating Rules',
      description: 'Generating Sigma/YARA rule structure',
      estimatedDuration: 5
    },
    {
      id: 'enrichment',
      name: 'Adding Context',
      description: 'Enriching with MITRE ATT&CK mappings',
      estimatedDuration: 2
    },
    {
      id: 'export',
      name: 'Formatting Output',
      description: 'Preparing final rule format',
      estimatedDuration: 1
    }
  ],

  URL_SCANNING: [
    {
      id: 'fetching',
      name: 'Fetching Content',
      description: 'Downloading webpage content',
      estimatedDuration: 5
    },
    {
      id: 'parsing',
      name: 'Parsing HTML',
      description: 'Extracting text and metadata',
      estimatedDuration: 2
    },
    {
      id: 'analysis',
      name: 'Threat Analysis',
      description: 'Analyzing content for threats',
      estimatedDuration: 8
    },
    {
      id: 'ioc_extraction',
      name: 'Extracting IOCs',
      description: 'Identifying indicators in content',
      estimatedDuration: 3
    }
  ],

  AI_ANALYSIS: [
    {
      id: 'preparation',
      name: 'Preparing Request',
      description: 'Formatting data for AI analysis',
      estimatedDuration: 1
    },
    {
      id: 'ai_processing',
      name: 'AI Processing',
      description: 'Analyzing with language model',
      estimatedDuration: 15
    },
    {
      id: 'parsing_response',
      name: 'Parsing Response',
      description: 'Extracting structured data from AI response',
      estimatedDuration: 2
    },
    {
      id: 'validation',
      name: 'Validating Results',
      description: 'Checking AI output for accuracy',
      estimatedDuration: 2
    }
  ]
};

// Helper function to create loading state
export const createLoadingState = (
  operation: keyof typeof LOADING_STAGES,
  currentStage: string,
  progress: number,
  message: string,
  completedStages: string[] = []
): LoadingState => {
  const stages = LOADING_STAGES[operation];
  const currentStageIndex = stages.findIndex(s => s.id === currentStage);
  
  // Calculate estimated time remaining
  let estimatedTimeRemaining = 0;
  for (let i = currentStageIndex; i < stages.length; i++) {
    const stage = stages[i];
    if (stage.estimatedDuration) {
      if (i === currentStageIndex) {
        // For current stage, calculate remaining time based on progress
        const stageProgress = progress - (i * (100 / stages.length));
        const stageProgressPercent = Math.max(0, stageProgress / (100 / stages.length));
        estimatedTimeRemaining += stage.estimatedDuration * (1 - stageProgressPercent);
      } else {
        // For future stages, add full duration
        estimatedTimeRemaining += stage.estimatedDuration;
      }
    }
  }

  return {
    currentStage,
    progress,
    message,
    estimatedTimeRemaining: estimatedTimeRemaining > 0 ? estimatedTimeRemaining : undefined,
    stages,
    completedStages
  };
};

export default ProfessionalLoader;
