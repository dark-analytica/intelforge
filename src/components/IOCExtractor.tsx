import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { extractIOCs, getIOCCounts, type IOCSet } from '@/lib/ioc-extractor';
import { Scan, Upload, Link } from 'lucide-react';
import { IOCList } from './IOCList';
import { TTpExtractor } from './TTpExtractor';

interface IOCExtractorProps {
  onIOCsExtracted: (iocs: IOCSet) => void;
  iocs: IOCSet;
}

export const IOCExtractor = ({ onIOCsExtracted, iocs }: IOCExtractorProps) => {
  const [inputText, setInputText] = useState('');
  const [includePrivate, setIncludePrivate] = useState(false);
  const [filterLegitimate, setFilterLegitimate] = useState(true);
  const [isExtracting, setIsExtracting] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [lastFetchedUrl, setLastFetchedUrl] = useState<string | null>(null);
  const { toast } = useToast();

  const counts = getIOCCounts(iocs);

  const handleExtractIOCs = () => {
    if (!inputText.trim()) return;
    
    setIsExtracting(true);
    setTimeout(() => {
      const extractedIOCs = extractIOCs(inputText, includePrivate, filterLegitimate, lastFetchedUrl || undefined);
      onIOCsExtracted(extractedIOCs);
      setIsExtracting(false);
    }, 500); // Simulate processing time
  };

  const handleFetchURL = async () => {
    const raw = urlInput.trim();
    if (!raw) return;
    const url = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;

    setIsExtracting(true);
    try {
      const proxy = localStorage.getItem('cqlforge_proxy_url');
      const fetchUrl = proxy ? `${proxy}?url=${encodeURIComponent(url)}` : url;
      const res = await fetch(fetchUrl);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      setInputText(text);
      setLastFetchedUrl(url);
      const extracted = extractIOCs(text, includePrivate, filterLegitimate, url);
      onIOCsExtracted(extracted);
      toast({ title: 'Fetched URL', description: 'Content loaded and IOCs extracted automatically.' });
    } catch (e: any) {
      // Fallback to a public, read-only CORS-friendly fetcher
      try {
        const alt = `https://r.jina.ai/http://${url.replace(/^https?:\/\//i, '')}`;
        const res2 = await fetch(alt);
        if (!res2.ok) throw new Error(`HTTP ${res2.status}`);
        const text2 = await res2.text();
        setInputText(text2);
        setLastFetchedUrl(url);
        const extracted = extractIOCs(text2, includePrivate, filterLegitimate, url);
        onIOCsExtracted(extracted);
        toast({ title: 'Fetched via fallback', description: 'Content loaded and IOCs extracted automatically.' });
      } catch {
        toast({ title: 'Fetch failed', description: 'CORS or network blocked. Configure a proxy in Settings.', variant: 'destructive' });
      }
    } finally {
      setIsExtracting(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsExtracting(true);
    try {
      let text = '';
      
      if (file.type === 'application/pdf') {
        // PDF parsing using pdfjs-dist
        const pdfjs = await import('pdfjs-dist');
        pdfjs.GlobalWorkerOptions.workerSrc = 'https://unpkg.com/pdfjs-dist@latest/build/pdf.worker.min.js';
        
        const fileBuffer = await file.arrayBuffer();
        const pdf = await pdfjs.getDocument({ data: fileBuffer }).promise;
        
        const textParts: string[] = [];
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const content = await page.getTextContent();
          const pageText = content.items
            .filter((item): item is any => 'str' in item)
            .map((item: any) => item.str)
            .join(' ');
          textParts.push(pageText);
        }
        text = textParts.join('\n\n');
        toast({ title: 'PDF Processed', description: `Extracted text from ${pdf.numPages} pages` });
      } else {
        // Regular text file
        const reader = new FileReader();
        text = await new Promise<string>((resolve, reject) => {
          reader.onload = (e) => resolve(e.target?.result as string);
          reader.onerror = () => reject(new Error('Failed to read file'));
          reader.readAsText(file);
        });
        toast({ title: 'File Loaded', description: 'Text file content loaded' });
      }
      
      setInputText(text);
    } catch (error: any) {
      console.error('File processing error:', error);
      toast({ 
        title: 'File Processing Failed', 
        description: error.message || 'Failed to process the uploaded file',
        variant: 'destructive' 
      });
    } finally {
      setIsExtracting(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="font-terminal text-glow">CTI Ingest</CardTitle>
          <CardDescription>
            Paste CTI text, upload a file, or enter a URL to extract IOCs
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder="Paste your cyber threat intelligence text here..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            className="min-h-[200px] font-code"
          />
          
          <div className="flex items-center gap-4">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="includePrivate"
                checked={includePrivate}
                onCheckedChange={(checked) => setIncludePrivate(checked as boolean)}
              />
              <label htmlFor="includePrivate" className="text-sm">
                Include private IP ranges
              </label>
            </div>
            
            <div className="flex items-center space-x-2">
              <Checkbox
                id="filterLegitimate"
                checked={filterLegitimate}
                onCheckedChange={(checked) => setFilterLegitimate(checked as boolean)}
              />
              <label htmlFor="filterLegitimate" className="text-sm">
                Filter website navigation (recommended)
              </label>
            </div>
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="https://example.com/cti.txt"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="font-code"
            />
            <Button variant="outline" className="gap-2" onClick={handleFetchURL}>
              <Link className="h-4 w-4" />
              Fetch URL
            </Button>
          </div>

          <div className="flex gap-2">
            <Button 
              onClick={handleExtractIOCs}
              disabled={!inputText.trim() || isExtracting}
              className="gap-2"
            >
              <Scan className="h-4 w-4" />
              {isExtracting ? 'Extracting...' : 'Extract IOCs'}
            </Button>
            
            <Button variant="outline" className="gap-2" asChild>
              <label htmlFor="file-upload" className="cursor-pointer">
                <Upload className="h-4 w-4" />
                Upload File
              </label>
            </Button>
            <input
              id="file-upload"
              type="file"
              accept=".txt,.pdf"
              className="hidden"
              onChange={handleFileUpload}
            />
          </div>
        </CardContent>
      </Card>

      
      <IOCList iocs={iocs} onIOCsUpdated={onIOCsExtracted} />
      
      <TTpExtractor text={inputText} />
    </div>
  );
};