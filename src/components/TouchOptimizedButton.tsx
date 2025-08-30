import React from 'react';
import { Button, ButtonProps } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useIsTouchDevice } from '@/hooks/useMediaQuery';

interface TouchOptimizedButtonProps extends ButtonProps {
  touchSize?: 'sm' | 'md' | 'lg';
}

export const TouchOptimizedButton: React.FC<TouchOptimizedButtonProps> = ({
  className,
  touchSize = 'md',
  children,
  ...props
}) => {
  const isTouchDevice = useIsTouchDevice();
  
  const touchSizeClasses = {
    sm: 'min-h-[40px] min-w-[40px] px-3 py-2',
    md: 'min-h-[44px] min-w-[44px] px-4 py-3',
    lg: 'min-h-[48px] min-w-[48px] px-6 py-4'
  };
  
  return (
    <Button
      className={cn(
        isTouchDevice && touchSizeClasses[touchSize],
        'touch-manipulation select-none',
        className
      )}
      {...props}
    >
      {children}
    </Button>
  );
};
