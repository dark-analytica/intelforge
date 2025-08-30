import { useState, useCallback, useRef, useEffect } from 'react';

interface DragAndDropOptions {
  onFileDrop: (files: FileList) => void;
  acceptedTypes?: string[];
  maxFiles?: number;
  maxSize?: number; // in bytes
  onError?: (error: string) => void;
}

interface DragAndDropState {
  isDragActive: boolean;
  isDragAccept: boolean;
  isDragReject: boolean;
}

export const useDragAndDrop = ({
  onFileDrop,
  acceptedTypes = [],
  maxFiles = 1,
  maxSize = 50 * 1024 * 1024, // 50MB default
  onError
}: DragAndDropOptions) => {
  const [dragState, setDragState] = useState<DragAndDropState>({
    isDragActive: false,
    isDragAccept: false,
    isDragReject: false
  });

  const dragCounter = useRef(0);

  const validateFiles = useCallback((files: FileList): boolean => {
    // Check file count
    if (files.length > maxFiles) {
      onError?.(`Maximum ${maxFiles} file(s) allowed`);
      return false;
    }

    // Check each file
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      
      // Check file size
      if (file.size > maxSize) {
        onError?.(`File "${file.name}" is too large. Maximum size: ${Math.round(maxSize / 1024 / 1024)}MB`);
        return false;
      }

      // Check file type if specified
      if (acceptedTypes.length > 0) {
        const isAccepted = acceptedTypes.some(type => {
          if (type.startsWith('.')) {
            return file.name.toLowerCase().endsWith(type.toLowerCase());
          }
          return file.type.match(type);
        });

        if (!isAccepted) {
          onError?.(`File type "${file.type || 'unknown'}" not supported. Accepted types: ${acceptedTypes.join(', ')}`);
          return false;
        }
      }
    }

    return true;
  }, [acceptedTypes, maxFiles, maxSize, onError]);

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    dragCounter.current++;
    
    if (e.dataTransfer?.items) {
      const hasFiles = Array.from(e.dataTransfer.items).some(
        item => item.kind === 'file'
      );
      
      if (hasFiles) {
        const isAccepted = acceptedTypes.length === 0 || 
          Array.from(e.dataTransfer.items).some(item => {
            if (item.kind === 'file') {
              const file = item.getAsFile();
              if (!file) return false;
              
              return acceptedTypes.some(type => {
                if (type.startsWith('.')) {
                  return file.name.toLowerCase().endsWith(type.toLowerCase());
                }
                return file.type.match(type);
              });
            }
            return false;
          });

        setDragState({
          isDragActive: true,
          isDragAccept: isAccepted,
          isDragReject: !isAccepted
        });
      }
    }
  }, [acceptedTypes]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    dragCounter.current--;
    
    if (dragCounter.current === 0) {
      setDragState({
        isDragActive: false,
        isDragAccept: false,
        isDragReject: false
      });
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    // Set the dropEffect to indicate this is a valid drop target
    if (e.dataTransfer) {
      e.dataTransfer.dropEffect = 'copy';
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    dragCounter.current = 0;
    setDragState({
      isDragActive: false,
      isDragAccept: false,
      isDragReject: false
    });

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      if (validateFiles(files)) {
        onFileDrop(files);
      }
    }
  }, [onFileDrop, validateFiles]);

  const getRootProps = useCallback(() => ({
    onDragEnter: handleDragEnter,
    onDragLeave: handleDragLeave,
    onDragOver: handleDragOver,
    onDrop: handleDrop
  }), [handleDragEnter, handleDragLeave, handleDragOver, handleDrop]);

  const getInputProps = useCallback(() => ({
    type: 'file' as const,
    multiple: maxFiles > 1,
    accept: acceptedTypes.join(','),
    style: { display: 'none' }
  }), [acceptedTypes, maxFiles]);

  // Note: Global listeners removed to avoid type conflicts
  // Drag and drop will work within the component boundaries

  return {
    ...dragState,
    getRootProps,
    getInputProps
  };
};
