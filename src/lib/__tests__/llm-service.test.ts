import { describe, it, expect, beforeEach, vi } from 'vitest';
import { llmService } from '../llm-service';
import { secureStorage } from '../secure-storage';

// Mock secure storage
vi.mock('../secure-storage', () => ({
  secureStorage: {
    encryptAndStore: vi.fn(),
    decryptAndRetrieve: vi.fn(),
    remove: vi.fn()
  }
}));

// Mock fetch for API calls
global.fetch = vi.fn();

describe('LLM Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('hasConfiguredProviders', () => {
    it('should return true when API keys are configured', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockResolvedValueOnce('test-openai-key')
        .mockResolvedValueOnce('')
        .mockResolvedValueOnce('')
        .mockResolvedValueOnce('');

      const result = await llmService.hasConfiguredProviders();
      expect(result).toBe(true);
    });

    it('should return false when no API keys are configured', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockResolvedValue('');

      const result = await llmService.hasConfiguredProviders();
      expect(result).toBe(false);
    });
  });

  describe('getConfiguredProviders', () => {
    it('should return list of configured providers', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockImplementation(async (key: string) => {
          if (key === 'cqlforge_openai_key') return 'test-openai-key';
          if (key === 'cqlforge_anthropic_key') return 'test-anthropic-key';
          return '';
        });

      const result = await llmService.getConfiguredProviders();
      expect(result).toContain('OpenAI');
      expect(result).toContain('Anthropic');
      expect(result).not.toContain('Google Gemini');
      expect(result).not.toContain('OpenRouter');
    });

    it('should return empty array when no providers configured', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockResolvedValue('');

      const result = await llmService.getConfiguredProviders();
      expect(result).toEqual([]);
    });
  });

  describe('generateCQL', () => {
    it('should generate CQL query successfully', async () => {
      // Mock API key retrieval
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockImplementation(async (key: string) => {
          if (key === 'cqlforge_openai_key') return 'test-openai-key';
          return '';
        });

      // Mock successful API response
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: 'SELECT * FROM events WHERE dst_ip = "192.168.1.1"'
            }
          }],
          model: 'gpt-4o-mini',
          usage: {
            prompt_tokens: 50,
            completion_tokens: 25,
            total_tokens: 75
          }
        })
      } as Response);

      const result = await llmService.generateCQL({
        userPrompt: 'Find traffic to 192.168.1.1',
        preferredModel: 'gpt-4o-mini'
      });

      expect(result.content).toContain('SELECT * FROM events WHERE dst_ip = "192.168.1.1"');
      expect(result.model).toBe('gpt-4o-mini');
      expect(result.provider).toBe('openai');
      expect(result.usage?.totalTokens).toBe(75);
    });

    it('should throw error when no API keys configured', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockResolvedValue('');

      await expect(llmService.generateCQL({
        userPrompt: 'Test query',
        preferredModel: 'gpt-4o-mini'
      })).rejects.toThrow('No API keys configured');
    });

    it('should handle API errors gracefully', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockImplementation(async (key: string) => {
          if (key === 'cqlforge_openai_key') return 'test-openai-key';
          return '';
        });

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized'
      } as Response);

      await expect(llmService.generateCQL({
        userPrompt: 'Test query',
        preferredModel: 'gpt-4o-mini'
      })).rejects.toThrow();
    });
  });

  describe('extractTTPs', () => {
    it('should extract TTPs from text successfully', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockImplementation(async (key: string) => {
          if (key === 'cqlforge_anthropic_key') return 'test-anthropic-key';
          return '';
        });

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          content: [{
            text: JSON.stringify({
              ttps: [
                {
                  technique_id: 'T1566.001',
                  technique_name: 'Spearphishing Attachment',
                  tactic: 'Initial Access',
                  behavior: 'Email with malicious attachment'
                }
              ],
              detections: [
                {
                  title: 'Email Attachment Analysis',
                  description: 'Monitor for suspicious email attachments'
                }
              ]
            })
          }],
          model: 'claude-3-haiku-20240307',
          usage: {
            input_tokens: 100,
            output_tokens: 200
          }
        })
      } as Response);

      const result = await llmService.extractTTPs({
        userPrompt: 'Analyze this threat report for TTPs',
        preferredModel: 'claude-3-haiku-20240307'
      });

      expect(result.content).toContain('T1566.001');
      expect(result.model).toBe('claude-3-haiku-20240307');
      expect(result.provider).toBe('anthropic');
    });
  });

  describe('Input sanitization', () => {
    it('should sanitize malicious input', () => {
      const maliciousInput = '<script>alert("xss")</script>DROP TABLE users;';
      const sanitized = llmService.sanitizeInput(maliciousInput);
      
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('DROP TABLE');
    });

    it('should preserve legitimate IOCs in input', () => {
      const legitimateInput = 'IP: 192.168.1.1, Domain: malicious.com, Hash: abc123';
      const sanitized = llmService.sanitizeInput(legitimateInput);
      
      expect(sanitized).toContain('192.168.1.1');
      expect(sanitized).toContain('malicious.com');
      expect(sanitized).toContain('abc123');
    });
  });

  describe('Error recovery', () => {
    it('should retry failed requests', async () => {
      vi.mocked(secureStorage.decryptAndRetrieve)
        .mockImplementation(async (key: string) => {
          if (key === 'cqlforge_openai_key') return 'test-openai-key';
          return '';
        });

      // First call fails, second succeeds
      vi.mocked(fetch)
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            choices: [{ message: { content: 'SELECT * FROM events' } }],
            model: 'gpt-4o-mini'
          })
        } as Response);

      const result = await llmService.generateCQL({
        userPrompt: 'Test query',
        preferredModel: 'gpt-4o-mini'
      });

      expect(result.content).toContain('SELECT * FROM events');
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });
});
