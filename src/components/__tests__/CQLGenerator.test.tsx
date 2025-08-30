import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CQLGenerator } from '../CQLGenerator';
import type { IOCSet } from '../../lib/ioc-extractor';

// Mock the CQL templates
vi.mock('../../lib/cql-templates', () => ({
  cqlTemplates: [
    {
      id: 'ip-investigation',
      name: 'IP Address Investigation',
      description: 'Investigate suspicious IP addresses',
      template: 'SELECT * FROM events WHERE dst_ip IN ({IP_LIST})',
      requiredIOCTypes: ['ipv4'],
      category: 'Network'
    },
    {
      id: 'domain-hunt',
      name: 'Domain Hunting',
      description: 'Hunt for malicious domains',
      template: 'SELECT * FROM events WHERE domain IN ({DOMAIN_LIST})',
      requiredIOCTypes: ['domains'],
      category: 'Network'
    }
  ],
  renderTemplate: vi.fn()
}));

// Mock vendor configurations
vi.mock('../../lib/vendor-configs', () => ({
  vendors: [
    {
      id: 'crowdstrike',
      name: 'CrowdStrike',
      modules: [
        {
          id: 'falcon-data-replicator',
          name: 'Falcon Data Replicator',
          description: 'CrowdStrike Falcon EDR data'
        }
      ]
    }
  ]
}));

describe('CQLGenerator', () => {
  const mockIOCs: IOCSet = {
    ipv4: ['192.168.1.100', '10.0.0.1'],
    ipv6: [],
    domains: ['malicious.com', 'evil.org'],
    urls: ['https://malicious.com/payload'],
    sha256: ['a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'],
    md5: ['5d41402abc4b2a76b9719d911017c592'],
    emails: ['attacker@malicious.com']
  };

  const mockOnQueriesGenerated = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render CQL Generator component', () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    expect(screen.getByText('Vendor-Aware CQL Generator')).toBeInTheDocument();
    expect(screen.getByText('Generate Queries')).toBeInTheDocument();
  });

  it('should display IOC counts correctly', () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    expect(screen.getByText('2 IPs')).toBeInTheDocument();
    expect(screen.getByText('2 Domains')).toBeInTheDocument();
    expect(screen.getByText('1 URL')).toBeInTheDocument();
    expect(screen.getByText('1 SHA256')).toBeInTheDocument();
  });

  it('should filter templates based on available IOCs', () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    // Should show IP template since we have IPs
    expect(screen.getByText('IP Address Investigation')).toBeInTheDocument();
    // Should show domain template since we have domains
    expect(screen.getByText('Domain Hunting')).toBeInTheDocument();
  });

  it('should generate queries when template is selected', async () => {
    const mockRenderTemplate = vi.mocked(await import('../../lib/cql-templates')).renderTemplate;
    mockRenderTemplate.mockReturnValue('SELECT * FROM events WHERE dst_ip IN ("192.168.1.100", "10.0.0.1")');

    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    // Select a template
    fireEvent.click(screen.getByText('IP Address Investigation'));
    
    // Click generate
    fireEvent.click(screen.getByText('Generate Queries'));
    
    await waitFor(() => {
      expect(mockOnQueriesGenerated).toHaveBeenCalled();
    });
  });

  it('should show warning when no IOCs are available', () => {
    const emptyIOCs: IOCSet = {
      ipv4: [], ipv6: [], domains: [], urls: [], sha256: [], md5: [], emails: []
    };

    render(<CQLGenerator iocs={emptyIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    expect(screen.getByText('No IOCs available')).toBeInTheDocument();
  });

  it('should disable generate button when no template is selected', () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    const generateButton = screen.getByText('Generate Queries');
    expect(generateButton).toBeDisabled();
  });

  it('should enable generate button when template is selected', async () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    // Select a template
    fireEvent.click(screen.getByText('IP Address Investigation'));
    
    await waitFor(() => {
      const generateButton = screen.getByText('Generate Queries');
      expect(generateButton).not.toBeDisabled();
    });
  });

  it('should handle vendor selection', () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    // Should have CrowdStrike selected by default
    expect(screen.getByDisplayValue('crowdstrike')).toBeInTheDocument();
  });

  it('should show template categories', () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    expect(screen.getByText('Network')).toBeInTheDocument();
  });

  it('should display template descriptions on hover or selection', async () => {
    render(<CQLGenerator iocs={mockIOCs} onQueriesGenerated={mockOnQueriesGenerated} />);
    
    fireEvent.click(screen.getByText('IP Address Investigation'));
    
    await waitFor(() => {
      expect(screen.getByText('Investigate suspicious IP addresses')).toBeInTheDocument();
    });
  });
});
