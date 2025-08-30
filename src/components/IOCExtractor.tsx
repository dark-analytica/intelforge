import React, { useState, useCallback, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { BatchProgressIndicator } from '@/components/BatchProgressIndicator';
import { ResponsiveLayout, ResponsiveGrid, ResponsiveStack } from './ResponsiveLayout';
import { TouchOptimizedButton } from './TouchOptimizedButton';
import { DragDropZone } from '@/components/DragDropZone';
import { WorkInProgressIndicator } from './WorkInProgressIndicator';
import { useWorkInProgress } from '@/hooks/useWorkInProgress';
import { IOCList } from './IOCList';
import { TTpExtractor } from './TTpExtractor';
import { extractIOCs, extractIOCsWithBatching, getIOCCounts, type IOCSet } from '@/lib/ioc-extractor';
import { useErrorHandler } from '@/hooks/useErrorHandler';
import { useIsMobile, useIsTouchDevice } from '@/hooks/useMediaQuery';
import { analytics, trackUserAction } from '@/lib/analytics';
import { 
  Upload, 
  FileText, 
  Globe, 
  Search, 
  AlertCircle, 
  CheckCircle2, 
  Loader2,
  X,
  Download
} from 'lucide-react';
import { URLScanner } from '@/lib/url-scanner';

interface IOCExtractorProps {
  onIOCsExtracted: (iocs: IOCSet) => void;
  iocs: IOCSet;
  onTTPsExtracted?: (ttps: any[], detections: any[], entities: any) => void;
}

export const IOCExtractor: React.FC<IOCExtractorProps> = ({ onIOCsExtracted, iocs, onTTPsExtracted }) => {
  const [text, setText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [extractedIOCs, setExtractedIOCs] = useState<IOCSet | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [urlInput, setUrlInput] = useState('');
  const [isUrlLoading, setIsUrlLoading] = useState(false);
  const [batchProgress, setBatchProgress] = useState<any>(null);
  const [showBatchProgress, setShowBatchProgress] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { handleError } = useErrorHandler();
  const isMobile = useIsMobile();
  const isTouchDevice = useIsTouchDevice();

  const handleTextExtraction = useCallback(async () => {
    if (!text.trim()) {
      handleError({
        title: "No text provided",
        description: "Please enter some text to extract IOCs from.",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    setBatchProgress(null);
    setShowBatchProgress(false);

    try {
      let extractedIOCs: IOCSet;

      const shouldUseBatching = text.length > 100000;

      if (shouldUseBatching) {
        setShowBatchProgress(true);
        extractedIOCs = await extractIOCsWithBatching(
          text,
          true,
          true,
          (progress) => {
            setBatchProgress(progress);
          }
        );
      } else {
        extractedIOCs = extractIOCs(text, true);
      }

      setExtractedIOCs(extractedIOCs);
      onIOCsExtracted(extractedIOCs);

      const counts = getIOCCounts(extractedIOCs);
      console.log(`IOCs extracted successfully: Found ${counts.total} IOCs (${counts.ipv4} IPs, ${counts.domains} domains, ${counts.urls} URLs, ${counts.sha256 + counts.md5} hashes, ${counts.emails} emails)${shouldUseBatching ? ' using batch processing' : ''}`);
    } catch (error) {
      console.error('IOC extraction failed:', error);
      const errorMessage = error instanceof Error ? error.message : "An unknown error occurred";
      handleError(new Error(errorMessage));
    } finally {
      setIsLoading(false);
      setShowBatchProgress(false);
      setBatchProgress(null);
    }
  }, [text, onIOCsExtracted]);

  const handleURLScan = useCallback(async () => {
    if (!urlInput.trim()) {
      handleError(new Error("Please enter a URL to scan"));
      return;
    }

    setIsUrlLoading(true);

    try {
      const urlScanner = new URLScanner();
      const scanResult = await urlScanner.scanURL(urlInput);

      if (scanResult.iocs) {
        // Set the content for TTP analysis
        setText(scanResult.content);
        
        setExtractedIOCs(scanResult.iocs);
        onIOCsExtracted(scanResult.iocs);

        const counts = getIOCCounts(scanResult.iocs);
        console.log(`URL scanned successfully: Found ${counts.total} IOCs from ${urlInput}. Content available for TTP analysis.`);
      } else {
        throw new Error(scanResult.error || 'Failed to scan URL');
      }
    } catch (error) {
      console.error('URL scan failed:', error);
      handleError({
        title: "URL scan failed",
        description: error instanceof Error ? error.message : "Failed to scan URL",
        variant: "destructive"
      });
    } finally {
      setIsUrlLoading(false);
    }
  }, [urlInput, onIOCsExtracted]);

  const handleFileProcessing = useCallback(async (file: File) => {
    setIsLoading(true);
    setError(null);

    try {
      let fileText = '';

      // Handle text-based files only
      const reader = new FileReader();
      fileText = await new Promise<string>((resolve, reject) => {
        reader.onload = (e) => {
          const result = e.target?.result;
          if (typeof result === 'string') {
            resolve(result);
          } else {
            reject(new Error('Failed to read file as text'));
          }
        };
        reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`));
        reader.readAsText(file, 'UTF-8');
      });

      setText(fileText);

      // Extract IOCs from the text
      const extractedIOCs = extractIOCs(fileText, true, true);

      setExtractedIOCs(extractedIOCs);
      onIOCsExtracted(extractedIOCs);

      const counts = getIOCCounts(extractedIOCs);
      
      // Show success message without using handleError to avoid object serialization issues
      console.log(`File processed successfully: Found ${counts.total} IOCs from ${file.name}`);
      
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to process file';
      setError(errorMessage);
      handleError(new Error(errorMessage));
    } finally {
      setIsLoading(false);
      setShowBatchProgress(false);
      setBatchProgress(null);
    }
  }, [onIOCsExtracted, handleError]);

  const handleFileUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    await handleFileProcessing(file);
  }, [handleFileProcessing]);

  return (
    <ResponsiveLayout className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            IOC Extraction
          </CardTitle>
          <CardDescription>
            Extract Indicators of Compromise from text, files, or URLs
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="text" className="w-full">
            <TabsList className={`grid w-full ${isMobile ? 'grid-cols-1 h-auto' : 'grid-cols-3'}`}>
              <TabsTrigger value="text" className={isMobile ? 'w-full mb-1' : ''}>
                <FileText className="h-4 w-4 mr-2" />
                Text Input
              </TabsTrigger>
              <TabsTrigger value="file" className={isMobile ? 'w-full mb-1' : ''}>
                <Upload className="h-4 w-4 mr-2" />
                File Upload
              </TabsTrigger>
              <TabsTrigger value="url" className={isMobile ? 'w-full' : ''}>
                <Globe className="h-4 w-4 mr-2" />
                URL Scan
              </TabsTrigger>
            </TabsList>
            <TabsContent value="text" className="space-y-4">
              <div>
                <Label htmlFor="ioc-text">Paste your text containing IOCs</Label>
                <Textarea
                  id="ioc-text"
                  placeholder="Paste threat intelligence reports, logs, or any text containing IOCs..."
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  className={`font-mono text-sm ${isMobile ? 'min-h-[150px] text-base' : 'min-h-[200px]'}`}
                />
              </div>
              <TouchOptimizedButton 
                onClick={handleTextExtraction} 
                disabled={!text.trim() || isLoading}
                className="w-full"
                touchSize={isMobile ? 'lg' : 'md'}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Extracting IOCs...
                  </>
                ) : (
                  <>
                    <Search className="mr-2 h-4 w-4" />
                    Extract IOCs
                  </>
                )}
              </TouchOptimizedButton>
            </TabsContent>
            <TabsContent value="file" className="space-y-4">
              <DragDropZone
                onFileDrop={(files) => {
                  const file = files[0];
                  if (file) {
                    // Call the file processing directly instead of synthetic event
                    handleFileProcessing(file);
                  }
                }}
                acceptedTypes={['.txt', '.csv', '.json', '.xml', '.html', '.md']}
                maxFiles={1}
                maxSize={50 * 1024 * 1024}
                disabled={isLoading}
                fileInputRef={fileInputRef}
                onError={(error) => {
                  handleError({
                    title: "File Upload Error",
                    description: error,
                    variant: "destructive"
                  });
                }}
              />
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv,.json,.xml,.html,.md"
                onChange={handleFileUpload}
                className="hidden"
              />
            </TabsContent>
            <TabsContent value="url" className="space-y-4">
              <div>
                <Label htmlFor="url-input">Enter a URL to scan for IOCs</Label>
                <Input
                  id="url-input"
                  placeholder="https://example.com/cti.txt"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="font-mono text-sm"
                />
              </div>
              <TouchOptimizedButton 
                onClick={handleURLScan} 
                disabled={!urlInput.trim() || isUrlLoading}
                className="w-full"
                touchSize={isMobile ? 'lg' : 'md'}
              >
                {isUrlLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Scanning URL...
                  </>
                ) : (
                  <>
                    <Globe className="mr-2 h-4 w-4" />
                    Scan URL
                  </>
                )}
              </TouchOptimizedButton>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {extractedIOCs && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
                Extracted IOCs
              </span>
              <TouchOptimizedButton
                variant="ghost"
                size="sm"
                onClick={() => setExtractedIOCs(null)}
              >
                <X className="h-4 w-4" />
              </TouchOptimizedButton>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveGrid 
              cols={{ mobile: 2, tablet: 4, desktop: 4 }} 
              gap={{ mobile: 2, tablet: 4, desktop: 4 }}
              className="mb-6"
            >
              {Object.entries(extractedIOCs).map(([type, iocs]) => (
                <div key={type} className="text-center">
                  <div className={`font-bold text-primary ${isMobile ? 'text-xl' : 'text-2xl'}`}>{iocs.length}</div>
                  <div className={`text-muted-foreground capitalize ${isMobile ? 'text-xs' : 'text-sm'}`}>{type}</div>
                </div>
              ))}
            </ResponsiveGrid>
          </CardContent>
        </Card>
      )}

      {/* Batch Progress Indicator */}
      {showBatchProgress && batchProgress && (
        <BatchProgressIndicator
          {...batchProgress}
          isVisible={showBatchProgress}
        />
      )}

      {/* Display extracted IOCs */}
      {extractedIOCs && (
        <IOCList 
          iocs={extractedIOCs} 
          onIOCsUpdated={(updatedIOCs) => {
            setExtractedIOCs(updatedIOCs);
            onIOCsExtracted(updatedIOCs);
          }} 
        />
      )}

      {/* TTP Extractor for AI-powered analysis */}
      {(text || extractedIOCs) && (
        <TTpExtractor 
          text={text}
          onTTPsExtracted={onTTPsExtracted}
        />
      )}
    </ResponsiveLayout>
  );
};