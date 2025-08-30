import React from 'react';
import { cn } from '@/lib/utils';
import { useDragAndDrop } from '@/hooks/useDragAndDrop';
import { useIsMobile } from '@/hooks/useMediaQuery';
import { Upload, FileText, AlertCircle, CheckCircle2 } from 'lucide-react';

interface DragDropZoneProps {
  onFileDrop: (files: FileList) => void;
  acceptedTypes?: string[];
  maxFiles?: number;
  maxSize?: number;
  className?: string;
  children?: React.ReactNode;
  disabled?: boolean;
  onError?: (error: string) => void;
  fileInputRef?: React.RefObject<HTMLInputElement>;
}

export const DragDropZone: React.FC<DragDropZoneProps> = ({
  onFileDrop,
  acceptedTypes = ['.txt', '.pdf', '.doc', '.docx', '.csv', '.json', '.xml', '.html', '.md'],
  maxFiles = 1,
  maxSize = 50 * 1024 * 1024, // 50MB
  className,
  children,
  disabled = false,
  onError,
  fileInputRef
}) => {
  const isMobile = useIsMobile();
  
  const {
    isDragActive,
    isDragAccept,
    isDragReject,
    getRootProps,
    getInputProps
  } = useDragAndDrop({
    onFileDrop,
    acceptedTypes,
    maxFiles,
    maxSize,
    onError
  });

  const getZoneContent = () => {
    if (children) {
      return children;
    }

    if (isDragActive) {
      if (isDragAccept) {
        return (
          <div className="flex flex-col items-center justify-center p-8 text-center">
            <CheckCircle2 className="h-12 w-12 text-green-500 mb-4" />
            <p className="text-lg font-medium text-green-600">Drop files here</p>
            <p className="text-sm text-muted-foreground mt-1">
              Release to upload {maxFiles > 1 ? 'files' : 'file'}
            </p>
          </div>
        );
      } else {
        return (
          <div className="flex flex-col items-center justify-center p-8 text-center">
            <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
            <p className="text-lg font-medium text-red-600">Invalid file type</p>
            <p className="text-sm text-muted-foreground mt-1">
              Accepted: {acceptedTypes.join(', ')}
            </p>
          </div>
        );
      }
    }

    return (
      <div className="flex flex-col items-center justify-center p-8 text-center">
        <Upload className={`text-muted-foreground mb-4 ${isMobile ? 'h-8 w-8' : 'h-12 w-12'}`} />
        <div className="space-y-2">
          <p className={`font-medium ${isMobile ? 'text-sm' : 'text-lg'}`}>
            {isMobile ? 'Tap to upload' : 'Drag & drop files here'}
          </p>
          <p className={`text-muted-foreground ${isMobile ? 'text-xs' : 'text-sm'}`}>
            or click to browse
          </p>
          <p className={`text-muted-foreground ${isMobile ? 'text-xs' : 'text-sm'}`}>
            Supports: {acceptedTypes.slice(0, 3).join(', ')}
            {acceptedTypes.length > 3 && ` +${acceptedTypes.length - 3} more`}
          </p>
          <p className={`text-muted-foreground ${isMobile ? 'text-xs' : 'text-sm'}`}>
            Max size: {Math.round(maxSize / 1024 / 1024)}MB
          </p>
        </div>
      </div>
    );
  };

  const getBorderColor = () => {
    if (disabled) return 'border-muted';
    if (isDragReject) return 'border-red-500 bg-red-50/50';
    if (isDragAccept) return 'border-green-500 bg-green-50/50';
    if (isDragActive) return 'border-primary bg-primary/5';
    return 'border-dashed border-border hover:border-primary/50';
  };

  const handleClick = () => {
    if (!disabled && fileInputRef?.current) {
      fileInputRef.current.click();
    }
  };

  return (
    <div
      {...getRootProps()}
      onClick={handleClick}
      className={cn(
        'relative border-2 rounded-lg transition-all duration-200 cursor-pointer',
        getBorderColor(),
        disabled && 'cursor-not-allowed opacity-50',
        isMobile && 'touch-manipulation',
        className
      )}
    >
      <input {...getInputProps()} disabled={disabled} />
      {getZoneContent()}
      
      {/* Visual feedback overlay */}
      {isDragActive && (
        <div className="absolute inset-0 bg-background/80 backdrop-blur-sm rounded-lg flex items-center justify-center">
          <div className={`p-4 rounded-lg border-2 ${isDragAccept ? 'border-green-500 bg-green-50' : 'border-red-500 bg-red-50'}`}>
            {isDragAccept ? (
              <CheckCircle2 className="h-8 w-8 text-green-500" />
            ) : (
              <AlertCircle className="h-8 w-8 text-red-500" />
            )}
          </div>
        </div>
      )}
    </div>
  );
};
