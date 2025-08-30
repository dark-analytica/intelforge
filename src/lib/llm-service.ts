// LLM Service - Client-side API calls with multiple provider support
import { secureStorage } from './secure-storage';
import { rateLimiter } from './rate-limiter';
import { analytics } from './analytics';
import { withRecovery, handleErrorWithRecovery } from './recovery-service';

const LLM_PROVIDERS = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  gemini: 'Google Gemini',
  openrouter: 'OpenRouter'
};

interface LLMConfig {
  provider: 'openai' | 'anthropic' | 'gemini' | 'openrouter';
  apiKey: string;
  model: string;
  baseUrl?: string;
}

interface LLMRequest {
  systemPrompt: string;
  userPrompt: string;
  preferredModel?: string;
  maxTokens?: number;
  temperature?: number;
}

interface LLMResponse {
  content: string;
  model: string;
  provider: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

class LLMService {
  private async getStoredApiKeys() {
    try {
      const keys = await Promise.all([
        secureStorage.decryptAndRetrieve('openai_key').catch(() => null),
        secureStorage.decryptAndRetrieve('anthropic_key').catch(() => null),
        secureStorage.decryptAndRetrieve('gemini_key').catch(() => null),
        secureStorage.decryptAndRetrieve('openrouter_key').catch(() => null)
      ]);

      return {
        openai: keys[0],
        anthropic: keys[1],
        gemini: keys[2],
        openrouter: keys[3]
      };
    } catch (error) {
      console.error('Failed to retrieve API keys:', error);
      return { openai: null, anthropic: null, gemini: null, openrouter: null };
    }
  }

  async hasConfiguredProviders(): Promise<boolean> {
    const apiKeys = await this.getStoredApiKeys();
    return !!(apiKeys.openai || apiKeys.anthropic || apiKeys.gemini || apiKeys.openrouter);
  }

  async getConfiguredProviders(): Promise<string[]> {
    const apiKeys = await this.getStoredApiKeys();
    const providers: string[] = [];
    
    if (apiKeys.openai) providers.push('OpenAI');
    if (apiKeys.anthropic) providers.push('Anthropic');
    if (apiKeys.gemini) providers.push('Google Gemini');
    if (apiKeys.openrouter) providers.push('OpenRouter');
    
    return providers;
  }

  private async getAvailableConfigs(preferredModel?: string): Promise<LLMConfig[]> {
    const apiKeys = await this.getStoredApiKeys();
    const configs: LLMConfig[] = [];

    // Add configs based on available API keys
    if (apiKeys.openai) {
      configs.push({
        provider: 'openai',
        apiKey: apiKeys.openai,
        model: preferredModel?.startsWith('gpt') ? preferredModel : 'gpt-4'
      });
    }

    if (apiKeys.anthropic) {
      configs.push({
        provider: 'anthropic',
        apiKey: apiKeys.anthropic,
        model: preferredModel?.startsWith('claude') ? preferredModel : 'claude-3-haiku-20240307'
      });
    }

    if (apiKeys.gemini) {
      configs.push({
        provider: 'gemini',
        apiKey: apiKeys.gemini,
        model: preferredModel?.startsWith('gemini') ? preferredModel : 'gemini-pro'
      });
    }

    if (apiKeys.openrouter) {
      configs.push({
        provider: 'openrouter',
        apiKey: apiKeys.openrouter,
        model: preferredModel || 'anthropic/claude-3-haiku'
      });
    }

    return configs;
  }

  async generateCQL(request: LLMRequest): Promise<LLMResponse> {
    return withRecovery(async () => {
      const configs = await this.getAvailableConfigs(request.preferredModel);
      
      if (configs.length === 0) {
        throw new Error('No API keys configured. Please configure at least one LLM provider in Settings.');
      }

      let lastError: Error | null = null;

      for (const config of configs) {
        try {
          const response = await this.callProvider(config, {
            ...request,
            systemPrompt: this.getCQLSystemPrompt(),
            userPrompt: this.sanitizeInput(request.userPrompt)
          });
          return response;
        } catch (error) {
          lastError = error as Error;
          await handleErrorWithRecovery(lastError, `CQL generation with ${config.provider}`);
          continue;
        }
      }

      throw new Error(`Failed to generate CQL with all providers. Last error: ${lastError?.message}`);
    }, 'CQL generation', 2);
  }

  async extractTTPs(request: LLMRequest): Promise<LLMResponse> {
    return withRecovery(async () => {
      const configs = await this.getAvailableConfigs(request.preferredModel);
      
      if (configs.length === 0) {
        throw new Error('No API keys configured. Please configure at least one LLM provider in Settings.');
      }

      let lastError: Error | null = null;

      for (const config of configs) {
        try {
          const response = await this.callProvider(config, {
            ...request,
            systemPrompt: this.getTTPSystemPrompt(),
            userPrompt: this.sanitizeInput(request.userPrompt)
          });
          return response;
        } catch (error) {
          lastError = error as Error;
          await handleErrorWithRecovery(lastError, `TTP extraction with ${config.provider}`);
          continue;
        }
      }

      throw new Error(`Failed to extract TTPs with all providers. Last error: ${lastError?.message}`);
    }, 'TTP extraction', 2);
  }

  private async callProvider(config: LLMConfig, request: LLMRequest): Promise<LLMResponse> {
    const startTime = Date.now();
    
    // Use rate limiter to queue and execute the request
    return rateLimiter.executeRequest(
      config.provider,
      async () => {
        try {
          let response: LLMResponse;
          
          switch (config.provider) {
            case 'openai':
              response = await this.callOpenAI(config, request);
              break;
            case 'anthropic':
              response = await this.callAnthropic(config, request);
              break;
            case 'gemini':
              response = await this.callGemini(config, request);
              break;
            case 'openrouter':
              response = await this.callOpenRouter(config, request);
              break;
            default:
              throw new Error(`Unsupported provider: ${config.provider}`);
          }

          analytics.track('llm_call', {
            provider: config.provider,
            model: config.model,
            success: true,
            responseTime: Date.now() - startTime,
            tokenCount: response.usage?.totalTokens || 0
          }, 'LLMService');

          return response;
        } catch (error) {
          analytics.track('llm_call', {
            provider: config.provider,
            model: config.model,
            success: false,
            responseTime: Date.now() - startTime,
            error: (error as Error).message
          }, 'LLMService');
          throw error;
        }
      },
      // Higher priority for interactive requests
      request.userPrompt.length < 1000 ? 1 : 0
    );
  }

  private async callOpenAI(config: LLMConfig, request: LLMRequest): Promise<LLMResponse> {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: config.model,
        messages: [
          { role: 'system', content: request.systemPrompt },
          { role: 'user', content: request.userPrompt }
        ],
        max_tokens: request.maxTokens || 2000,
        temperature: request.temperature || 0.7
      })
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json();
    
    return {
      content: data.choices[0].message.content,
      model: data.model,
      provider: 'openai',
      usage: data.usage ? {
        promptTokens: data.usage.prompt_tokens,
        completionTokens: data.usage.completion_tokens,
        totalTokens: data.usage.total_tokens
      } : undefined
    };
  }

  private async callAnthropic(config: LLMConfig, request: LLMRequest): Promise<LLMResponse> {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': config.apiKey,
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: config.model,
        system: request.systemPrompt,
        messages: [{ role: 'user', content: request.userPrompt }],
        max_tokens: request.maxTokens || 2000,
        temperature: request.temperature || 0.7
      })
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    return {
      content: data.content[0].text,
      model: data.model,
      provider: 'anthropic',
      usage: data.usage ? {
        promptTokens: data.usage.input_tokens,
        completionTokens: data.usage.output_tokens,
        totalTokens: data.usage.input_tokens + data.usage.output_tokens
      } : undefined
    };
  }

  private async callGemini(config: LLMConfig, request: LLMRequest): Promise<LLMResponse> {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${config.model}:generateContent?key=${config.apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: `${request.systemPrompt}\n\n${request.userPrompt}`
          }]
        }],
        generationConfig: {
          maxOutputTokens: request.maxTokens || 2000,
          temperature: request.temperature || 0.7
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    return {
      content: data.candidates[0].content.parts[0].text,
      model: config.model,
      provider: 'gemini',
      usage: data.usageMetadata ? {
        promptTokens: data.usageMetadata.promptTokenCount,
        completionTokens: data.usageMetadata.candidatesTokenCount,
        totalTokens: data.usageMetadata.totalTokenCount
      } : undefined
    };
  }

  private async callOpenRouter(config: LLMConfig, request: LLMRequest): Promise<LLMResponse> {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': window.location.origin,
        'X-Title': 'IntelForge'
      },
      body: JSON.stringify({
        model: config.model,
        messages: [
          { role: 'system', content: request.systemPrompt },
          { role: 'user', content: request.userPrompt }
        ],
        max_tokens: request.maxTokens || 2000,
        temperature: request.temperature || 0.7
      })
    });

    if (!response.ok) {
      throw new Error(`OpenRouter API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    return {
      content: data.choices[0].message.content,
      model: data.model,
      provider: 'openrouter',
      usage: data.usage ? {
        promptTokens: data.usage.prompt_tokens,
        completionTokens: data.usage.completion_tokens,
        totalTokens: data.usage.total_tokens
      } : undefined
    };
  }

  private getCQLSystemPrompt(): string {
    return `You are a CrowdStrike Query Language (CQL) expert. Your task is to convert the given IOCs (Indicators of Compromise) into accurate CQL queries for threat hunting in CrowdStrike Falcon.

Key CQL Guidelines:
1. Use proper field names: event_simpleName, ComputerName, UserName, FileName, FilePath, CommandLine, etc.
2. Use correct operators: =, !=, contains, icontains, in, not in, matches, imatches
3. For IP addresses, use RemoteAddressIP4, LocalAddressIP4, or ConnectionDirection
4. For file hashes, use MD5HashData, SHA1HashData, or SHA256HashData
5. For domains, use DomainName or RemoteDomainName
6. Use parentheses for complex logic and proper AND/OR operators
7. Include time ranges when appropriate: earliest=-24h@h latest=now
8. Consider process relationships and parent-child processes

Provide only the CQL query without additional explanation unless specifically requested.`;
  }

  private getTTPSystemPrompt(): string {
    return `You are a cybersecurity expert specializing in MITRE ATT&CK framework analysis. Your task is to extract and identify Tactics, Techniques, and Procedures (TTPs) from the provided threat intelligence or incident data.

Guidelines:
1. Identify specific MITRE ATT&CK techniques with their IDs (e.g., T1055 - Process Injection)
2. Map techniques to appropriate tactics (e.g., Defense Evasion, Persistence, etc.)
3. Describe the procedures used by threat actors
4. Provide context on how these TTPs relate to the overall attack chain
5. Include sub-techniques when relevant (e.g., T1055.001 - Dynamic-link Library Injection)
6. Consider both technical and behavioral indicators

Format your response as a structured analysis with:
- Tactics: High-level adversary goals
- Techniques: Methods used to achieve tactics
- Procedures: Specific implementations observed
- Context: How these TTPs fit into the broader threat landscape

Be precise and reference official MITRE ATT&CK documentation when possible.`;
  }

  private sanitizeInput(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    // Remove potentially dangerous content
    return input
      .replace(/[<>]/g, '') // Remove angle brackets
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/data:/gi, '') // Remove data: protocol
      .trim()
      .substring(0, 10000); // Limit length
  }

}

export const llmService = new LLMService();
