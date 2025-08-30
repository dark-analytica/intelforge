import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { IOCExtractor } from '../IOCExtractor';
import userEvent from '@testing-library/user-event';
import type { IOCSet } from '../../lib/ioc-extractor';

// Mock the IOC extraction functions
vi.mock('../../lib/ioc-extractor', () => ({
  extractIOCs: vi.fn(),
  extractIOCsWithAI: vi.fn(),
  getIOCCounts: vi.fn()
}));

// Mock PDF.js
vi.mock('pdfjs-dist', () => ({
  getDocument: vi.fn(),
  GlobalWorkerOptions: { workerSrc: '' }
}));

// Mock fetch for URL fetching
global.fetch = vi.fn();

describe('IOCExtractor', () => {
  const mockOnIOCsExtracted = vi.fn();
  const mockOnTTPsExtracted = vi.fn();
  const mockIOCs: IOCSet = {
    ipv4: ['192.168.1.1'],
    ipv6: [],
    domains: ['malicious.com'],
    urls: ['https://evil.org'],
    sha256: ['abc123'],
    md5: ['def456'],
    emails: ['bad@evil.com']
  };

  const emptyIOCs: IOCSet = {
    ipv4: [], ipv6: [], domains: [], urls: [], sha256: [], md5: [], emails: []
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    
    // Mock getIOCCounts
    const { getIOCCounts } = await import('../../lib/ioc-extractor');
    vi.mocked(getIOCCounts).mockReturnValue({
      total: 4,
      ipv4: 1,
      ipv6: 0,
      domains: 1,
      urls: 1,
      sha256: 1,
      md5: 1,
      emails: 1
    });
  });

  it('should render IOC Extractor component', () => {
    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={mockIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    expect(screen.getByText('IOC Extraction Engine')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Paste threat intelligence/)).toBeInTheDocument();
  });

  it('should extract IOCs from text input', async () => {
    const mockExtractIOCs = vi.mocked(await import('../../lib/ioc-extractor')).extractIOCs;
    mockExtractIOCs.mockReturnValue(mockIOCs);

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    const textarea = screen.getByPlaceholderText(/Paste threat intelligence/);
    const extractButton = screen.getByText('Extract IOCs');
    
    await userEvent.type(textarea, 'Malicious IP: 192.168.1.1 and domain: malicious.com');
    fireEvent.click(extractButton);
    
    await waitFor(() => {
      expect(mockExtractIOCs).toHaveBeenCalledWith(
        'Malicious IP: 192.168.1.1 and domain: malicious.com',
        false,
        true,
        undefined,
        false
      );
      expect(mockOnIOCsExtracted).toHaveBeenCalledWith(mockIOCs);
    });
  });

  it('should handle AI filtering toggle', async () => {
    const iocExtractorModule = await import('../../lib/ioc-extractor');
    const mockExtractIOCsWithAI = vi.mocked(iocExtractorModule.extractIOCsWithAI);
    mockExtractIOCsWithAI.mockResolvedValue(mockIOCs);

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    // Enable AI filtering
    const aiToggle = screen.getByRole('checkbox', { name: /AI-powered IOC filtering/ });
    fireEvent.click(aiToggle);
    
    const textarea = screen.getByPlaceholderText(/Paste threat intelligence/);
    const extractButton = screen.getByText('Extract IOCs');
    
    await userEvent.type(textarea, 'Test content with IOCs');
    fireEvent.click(extractButton);
    
    await waitFor(() => {
      expect(mockExtractIOCsWithAI).toHaveBeenCalled();
    });
  });

  it('should handle private IP inclusion toggle', async () => {
    const mockExtractIOCs = vi.mocked(await import('../../lib/ioc-extractor')).extractIOCs;
    mockExtractIOCs.mockReturnValue(mockIOCs);

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    // Enable private IP inclusion
    const privateToggle = screen.getByRole('checkbox', { name: /Include private IPs/ });
    fireEvent.click(privateToggle);
    
    const textarea = screen.getByPlaceholderText(/Paste threat intelligence/);
    const extractButton = screen.getByText('Extract IOCs');
    
    await userEvent.type(textarea, 'Private IP: 192.168.1.1');
    fireEvent.click(extractButton);
    
    await waitFor(() => {
      expect(mockExtractIOCs).toHaveBeenCalledWith(
        'Private IP: 192.168.1.1',
        true, // includePrivate should be true
        true,
        undefined,
        false
      );
    });
  });

  it('should fetch URL content', async () => {
    const mockHtmlContent = '<html><body>IOC: 192.168.1.1</body></html>';
    
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      text: async () => mockHtmlContent
    } as Response);

    const mockExtractIOCs = vi.mocked(await import('../../lib/ioc-extractor')).extractIOCs;
    mockExtractIOCs.mockReturnValue(mockIOCs);

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    const urlInput = screen.getByPlaceholderText('Enter URL to fetch and analyze');
    const fetchButton = screen.getByText('Fetch URL');
    
    await userEvent.type(urlInput, 'https://malicious.com');
    fireEvent.click(fetchButton);
    
    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith('https://malicious.com');
      expect(mockOnIOCsExtracted).toHaveBeenCalledWith(mockIOCs);
    });
  });

  it('should handle URL fetch errors gracefully', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    const urlInput = screen.getByPlaceholderText('Enter URL to fetch and analyze');
    const fetchButton = screen.getByText('Fetch URL');
    
    await userEvent.type(urlInput, 'https://unreachable.com');
    fireEvent.click(fetchButton);
    
    await waitFor(() => {
      expect(screen.getByText(/Fetch failed/)).toBeInTheDocument();
    });
  });

  it('should handle file upload', async () => {
    const mockExtractIOCs = vi.mocked(await import('../../lib/ioc-extractor')).extractIOCs;
    mockExtractIOCs.mockReturnValue(mockIOCs);

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    const fileInput = screen.getByLabelText(/Upload File/);
    const file = new File(['IOC content: 192.168.1.1'], 'test.txt', { type: 'text/plain' });
    
    await userEvent.upload(fileInput, file);
    
    await waitFor(() => {
      expect(mockExtractIOCs).toHaveBeenCalled();
      expect(mockOnIOCsExtracted).toHaveBeenCalledWith(mockIOCs);
    });
  });

  it('should display IOC counts when IOCs are present', () => {
    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={mockIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    expect(screen.getByText('4 Total IOCs')).toBeInTheDocument();
    expect(screen.getByText('1 IP')).toBeInTheDocument();
    expect(screen.getByText('1 Domain')).toBeInTheDocument();
  });

  it('should show loading state during extraction', async () => {
    const mockExtractIOCs = vi.mocked(await import('../../lib/ioc-extractor')).extractIOCs;
    mockExtractIOCs.mockImplementation(() => {
      return new Promise(resolve => setTimeout(() => resolve(mockIOCs), 100));
    });

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    const textarea = screen.getByPlaceholderText(/Paste threat intelligence/);
    const extractButton = screen.getByText('Extract IOCs');
    
    await userEvent.type(textarea, 'Test content');
    fireEvent.click(extractButton);
    
    expect(screen.getByText('Extracting...')).toBeInTheDocument();
    
    await waitFor(() => {
      expect(screen.getByText('Extract IOCs')).toBeInTheDocument();
    });
  });

  it('should clear input when clear button is clicked', async () => {
    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    const textarea = screen.getByPlaceholderText(/Paste threat intelligence/);
    await userEvent.type(textarea, 'Some content to clear');
    
    const clearButton = screen.getByText('Clear');
    fireEvent.click(clearButton);
    
    expect(textarea).toHaveValue('');
  });

  it('should handle legitimate domain filtering toggle', async () => {
    const mockExtractIOCs = vi.mocked(await import('../../lib/ioc-extractor')).extractIOCs;
    mockExtractIOCs.mockReturnValue(mockIOCs);

    render(<IOCExtractor onIOCsExtracted={mockOnIOCsExtracted} iocs={emptyIOCs} onTTPsExtracted={mockOnTTPsExtracted} />);
    
    // Disable legitimate filtering
    const filterToggle = screen.getByRole('checkbox', { name: /Filter legitimate sites/ });
    fireEvent.click(filterToggle);
    
    const textarea = screen.getByPlaceholderText(/Paste threat intelligence/);
    const extractButton = screen.getByText('Extract IOCs');
    
    await userEvent.type(textarea, 'Domains: google.com, malicious.com');
    fireEvent.click(extractButton);
    
    await waitFor(() => {
      expect(mockExtractIOCs).toHaveBeenCalledWith(
        'Domains: google.com, malicious.com',
        false,
        false, // filterLegitimate should be false
        undefined,
        false
      );
    });
  });
});
