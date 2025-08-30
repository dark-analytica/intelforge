import { describe, it, expect, beforeEach } from 'vitest';
import { extractIOCs, extractIOCsWithAI, isLegitimateWebsiteDomain } from '../ioc-extractor';
import type { IOCSet } from '../ioc-extractor';

describe('IOC Extractor', () => {
  describe('extractIOCs', () => {
    it('should extract IPv4 addresses correctly', () => {
      const text = 'Malicious traffic from 192.168.1.100 and 10.0.0.1 detected.';
      const result = extractIOCs(text, false, false);
      
      expect(result.ipv4).toContain('192.168.1.100');
      expect(result.ipv4).toContain('10.0.0.1');
      expect(result.ipv4).toHaveLength(2);
    });

    it('should extract IPv6 addresses correctly', () => {
      const text = 'IPv6 address 2001:0db8:85a3:0000:0000:8a2e:0370:7334 found in logs.';
      const result = extractIOCs(text, false, false);
      
      expect(result.ipv6).toContain('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      expect(result.ipv6).toHaveLength(1);
    });

    it('should extract domain names correctly', () => {
      const text = 'C2 domains: malicious-domain.com, evil.example.org, and bad-actor.net';
      const result = extractIOCs(text, false, false);
      
      expect(result.domains).toContain('malicious-domain.com');
      expect(result.domains).toContain('evil.example.org');
      expect(result.domains).toContain('bad-actor.net');
      expect(result.domains).toHaveLength(3);
    });

    it('should extract URLs correctly', () => {
      const text = 'Phishing URLs: https://fake-bank.com/login and http://malware-drop.net/payload.exe';
      const result = extractIOCs(text, false, false);
      
      expect(result.urls).toContain('https://fake-bank.com/login');
      expect(result.urls).toContain('http://malware-drop.net/payload.exe');
      expect(result.urls).toHaveLength(2);
    });

    it('should extract SHA256 hashes correctly', () => {
      const text = 'File hash: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3';
      const result = extractIOCs(text, false, false);
      
      expect(result.sha256).toContain('a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3');
      expect(result.sha256).toHaveLength(1);
    });

    it('should extract MD5 hashes correctly', () => {
      const text = 'MD5: 5d41402abc4b2a76b9719d911017c592';
      const result = extractIOCs(text, false, false);
      
      expect(result.md5).toContain('5d41402abc4b2a76b9719d911017c592');
      expect(result.md5).toHaveLength(1);
    });

    it('should extract email addresses correctly', () => {
      const text = 'Phishing emails from attacker@malicious.com and spam@evil.org';
      const result = extractIOCs(text, false, false);
      
      expect(result.emails).toContain('attacker@malicious.com');
      expect(result.emails).toContain('spam@evil.org');
      expect(result.emails).toHaveLength(2);
    });

    it('should handle defanged IOCs correctly', () => {
      const text = 'Defanged: hxxp://malicious[.]com and 192[.]168[.]1[.]100';
      const result = extractIOCs(text, false, false);
      
      expect(result.urls).toContain('http://malicious.com');
      expect(result.ipv4).toContain('192.168.1.100');
    });

    it('should filter private IPs when includePrivate is false', () => {
      const text = 'IPs: 192.168.1.1, 10.0.0.1, 8.8.8.8, 172.16.0.1';
      const result = extractIOCs(text, false, false);
      
      expect(result.ipv4).toContain('8.8.8.8');
      expect(result.ipv4).not.toContain('192.168.1.1');
      expect(result.ipv4).not.toContain('10.0.0.1');
      expect(result.ipv4).not.toContain('172.16.0.1');
    });

    it('should include private IPs when includePrivate is true', () => {
      const text = 'IPs: 192.168.1.1, 10.0.0.1, 8.8.8.8';
      const result = extractIOCs(text, true, false);
      
      expect(result.ipv4).toContain('192.168.1.1');
      expect(result.ipv4).toContain('10.0.0.1');
      expect(result.ipv4).toContain('8.8.8.8');
      expect(result.ipv4).toHaveLength(3);
    });

    it('should filter legitimate domains when filterLegitimate is true', () => {
      const text = 'Domains: google.com, malicious-domain.com, microsoft.com';
      const result = extractIOCs(text, false, true);
      
      expect(result.domains).toContain('malicious-domain.com');
      expect(result.domains).not.toContain('google.com');
      expect(result.domains).not.toContain('microsoft.com');
    });

    it('should handle empty input gracefully', () => {
      const result = extractIOCs('', false, false);
      
      expect(result.ipv4).toHaveLength(0);
      expect(result.ipv6).toHaveLength(0);
      expect(result.domains).toHaveLength(0);
      expect(result.urls).toHaveLength(0);
      expect(result.sha256).toHaveLength(0);
      expect(result.md5).toHaveLength(0);
      expect(result.emails).toHaveLength(0);
    });

    it('should deduplicate IOCs', () => {
      const text = 'IP 8.8.8.8 appeared twice: 8.8.8.8';
      const result = extractIOCs(text, false, false);
      
      expect(result.ipv4).toContain('8.8.8.8');
      expect(result.ipv4).toHaveLength(1);
    });
  });

  describe('isLegitimateWebsiteDomain', () => {
    it('should identify legitimate domains correctly', () => {
      expect(isLegitimateWebsiteDomain('google.com')).toBe(true);
      expect(isLegitimateWebsiteDomain('microsoft.com')).toBe(true);
      expect(isLegitimateWebsiteDomain('github.com')).toBe(true);
      expect(isLegitimateWebsiteDomain('stackoverflow.com')).toBe(true);
    });

    it('should not flag suspicious domains as legitimate', () => {
      expect(isLegitimateWebsiteDomain('malicious-domain.com')).toBe(false);
      expect(isLegitimateWebsiteDomain('evil.example.org')).toBe(false);
      expect(isLegitimateWebsiteDomain('suspicious-site.net')).toBe(false);
    });

    it('should handle case insensitivity', () => {
      expect(isLegitimateWebsiteDomain('GOOGLE.COM')).toBe(true);
      expect(isLegitimateWebsiteDomain('Microsoft.COM')).toBe(true);
    });

    it('should handle subdomains of legitimate sites', () => {
      expect(isLegitimateWebsiteDomain('mail.google.com')).toBe(true);
      expect(isLegitimateWebsiteDomain('docs.microsoft.com')).toBe(true);
    });
  });

  describe('Complex IOC extraction scenarios', () => {
    it('should handle mixed IOC types in threat report', () => {
      const threatReport = `
        THREAT REPORT: APT29 Campaign
        
        C2 Infrastructure:
        - Primary C2: 203.0.113.45
        - Backup C2: malicious-c2.example.com
        - Exfil URL: https://data-exfil.evil.org/upload
        
        Malware Samples:
        - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        - MD5: d41d8cd98f00b204e9800998ecf8427e
        
        Phishing Campaign:
        - Sender: attacker@phishing-domain.net
        - Target: victim@company.com
      `;
      
      const result = extractIOCs(threatReport, false, false);
      
      expect(result.ipv4).toContain('203.0.113.45');
      expect(result.domains).toContain('malicious-c2.example.com');
      expect(result.urls).toContain('https://data-exfil.evil.org/upload');
      expect(result.sha256).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(result.md5).toContain('d41d8cd98f00b204e9800998ecf8427e');
      expect(result.emails).toContain('attacker@phishing-domain.net');
      expect(result.emails).toContain('victim@company.com');
    });

    it('should extract IOCs from URLs without duplicating domains', () => {
      const text = 'URL: https://malicious.com/path and domain: malicious.com';
      const result = extractIOCs(text, false, false);
      
      expect(result.urls).toContain('https://malicious.com/path');
      expect(result.domains).toContain('malicious.com');
      // Domain should appear only once, not duplicated from URL
      expect(result.domains.filter(d => d === 'malicious.com')).toHaveLength(1);
    });
  });
});
