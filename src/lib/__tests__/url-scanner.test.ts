import { describe, it, expect, beforeEach, vi } from 'vitest';
import { URLScanner } from '../url-scanner';

// Mock fetch for URL requests
global.fetch = vi.fn();

describe('URL Scanner', () => {
  let scanner: URLScanner;

  beforeEach(() => {
    vi.clearAllMocks();
    scanner = new URLScanner();
  });

  describe('scanURL', () => {
    it('should scan URL and extract IOCs successfully', async () => {
      const mockHtmlContent = `
        <html>
          <head><title>Malicious Site</title></head>
          <body>
            <p>Contact us at evil@malicious.com</p>
            <p>Download from http://malware.com/payload.exe</p>
            <p>C2 server: 203.0.113.45</p>
            <p>Hash: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3</p>
          </body>
        </html>
      `;

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => mockHtmlContent
      } as Response);

      const result = await scanner.scanURL('https://malicious.com');

      expect(result.url).toBe('https://malicious.com');
      expect(result.statusCode).toBe(200);
      expect(result.title).toBe('Malicious Site');
      expect(result.iocs.emails).toContain('evil@malicious.com');
      expect(result.iocs.urls).toContain('http://malware.com/payload.exe');
      expect(result.iocs.ipv4).toContain('203.0.113.45');
      expect(result.iocs.sha256).toContain('a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3');
    });

    it('should handle HTTP errors gracefully', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found'
      } as Response);

      const result = await scanner.scanURL('https://nonexistent.com');

      expect(result.url).toBe('https://nonexistent.com');
      expect(result.statusCode).toBe(0);
      expect(result.error).toContain('HTTP 404');
      expect(result.iocs.domains).toHaveLength(0);
    });

    it('should handle network errors', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));

      const result = await scanner.scanURL('https://unreachable.com');

      expect(result.url).toBe('https://unreachable.com');
      expect(result.error).toContain('Network error');
      expect(result.statusCode).toBe(0);
    });

    it('should reject invalid URLs', async () => {
      const result = await scanner.scanURL('ftp://invalid.com');

      expect(result.error).toContain('Only HTTP and HTTPS URLs are supported');
    });

    it('should extract title from HTML content', async () => {
      const htmlWithTitle = '<html><head><title>Test Page Title</title></head><body></body></html>';
      
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => htmlWithTitle
      } as Response);

      const result = await scanner.scanURL('https://test.com');

      expect(result.title).toBe('Test Page Title');
    });

    it('should handle missing title gracefully', async () => {
      const htmlWithoutTitle = '<html><body><h1>No Title</h1></body></html>';
      
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => htmlWithoutTitle
      } as Response);

      const result = await scanner.scanURL('https://test.com');

      expect(result.title).toBeUndefined();
    });

    it('should respect timeout option', async () => {
      const slowScanner = new URLScanner({ timeout: 100 });
      
      // Mock a slow response
      vi.mocked(fetch).mockImplementationOnce(() => 
        new Promise(resolve => setTimeout(resolve, 200))
      );

      const result = await slowScanner.scanURL('https://slow.com');

      expect(result.error).toBeDefined();
    });

    it('should filter legitimate domains when enabled', async () => {
      const htmlContent = `
        <html>
          <body>
            <p>Visit google.com and malicious.com</p>
            <p>Also check microsoft.com and evil.org</p>
          </body>
        </html>
      `;

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => htmlContent
      } as Response);

      const result = await scanner.scanURL('https://test.com', { filterLegitimate: true });

      expect(result.iocs.domains).toContain('malicious.com');
      expect(result.iocs.domains).toContain('evil.org');
      expect(result.iocs.domains).not.toContain('google.com');
      expect(result.iocs.domains).not.toContain('microsoft.com');
    });

    it('should include private IPs when enabled', async () => {
      const htmlContent = `
        <html>
          <body>
            <p>Internal servers: 192.168.1.1, 10.0.0.1</p>
            <p>External server: 8.8.8.8</p>
          </body>
        </html>
      `;

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => htmlContent
      } as Response);

      const result = await scanner.scanURL('https://test.com', { includePrivateIPs: true });

      expect(result.iocs.ipv4).toContain('192.168.1.1');
      expect(result.iocs.ipv4).toContain('10.0.0.1');
      expect(result.iocs.ipv4).toContain('8.8.8.8');
    });

    it('should limit content length when specified', async () => {
      const longContent = 'A'.repeat(10000);
      
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => longContent
      } as Response);

      const result = await scanner.scanURL('https://test.com', { maxContentLength: 1000 });

      expect(result.content.length).toBeLessThanOrEqual(1000);
    });
  });

  describe('Threat Assessment', () => {
    it('should provide basic threat assessment without AI', async () => {
      const suspiciousContent = `
        <html>
          <body>
            <p>Download malware from http://evil.com/trojan.exe</p>
            <p>C2: 203.0.113.45</p>
            <p>Phishing: fake-bank@evil.com</p>
          </body>
        </html>
      `;

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => suspiciousContent
      } as Response);

      const result = await scanner.scanURL('https://suspicious.com', { useAI: false });

      expect(result.threatAssessment).toBeDefined();
      expect(result.threatAssessment.riskLevel).toBeGreaterThan(0.5);
      expect(result.threatAssessment.indicators).toContain('Multiple IOC types detected');
    });

    it('should handle clean content assessment', async () => {
      const cleanContent = `
        <html>
          <body>
            <h1>Welcome to Our Company</h1>
            <p>Contact us at info@company.com</p>
            <p>Visit our partner at microsoft.com</p>
          </body>
        </html>
      `;

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => cleanContent
      } as Response);

      const result = await scanner.scanURL('https://legitimate.com', { 
        useAI: false,
        filterLegitimate: true 
      });

      expect(result.threatAssessment.riskLevel).toBeLessThan(0.3);
      expect(result.threatAssessment.confidence).toBeGreaterThan(0.7);
    });
  });

  describe('Fallback mechanisms', () => {
    it('should try fallback URLs when direct fetch fails', async () => {
      // First call (direct) fails with CORS
      vi.mocked(fetch)
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))
        .mockResolvedValueOnce({
          ok: true,
          text: async () => 'Fallback content with IOC: 192.168.1.1'
        } as Response);

      const result = await scanner.scanURL('https://cors-blocked.com');

      expect(result.content).toContain('Fallback content');
      expect(result.iocs.ipv4).toContain('192.168.1.1');
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Edge cases', () => {
    it('should handle empty response content', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => ''
      } as Response);

      const result = await scanner.scanURL('https://empty.com');

      expect(result.content).toBe('');
      expect(result.iocs.domains).toHaveLength(0);
      expect(result.statusCode).toBe(200);
    });

    it('should handle malformed HTML gracefully', async () => {
      const malformedHtml = '<html><head><title>Test</><body><p>Broken HTML<p>IOC: 192.168.1.1</body>';
      
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        text: async () => malformedHtml
      } as Response);

      const result = await scanner.scanURL('https://broken.com');

      expect(result.title).toBe('Test');
      expect(result.iocs.ipv4).toContain('192.168.1.1');
    });

    it('should measure scan time accurately', async () => {
      vi.mocked(fetch).mockImplementationOnce(() => 
        new Promise(resolve => 
          setTimeout(() => resolve({
            ok: true,
            text: async () => 'Test content'
          } as Response), 100)
        )
      );

      const result = await scanner.scanURL('https://test.com');

      expect(result.scanTime).toBeGreaterThan(90);
      expect(result.scanTime).toBeLessThan(200);
    });
  });
});
