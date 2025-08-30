import React from 'react';
import { cn } from '@/lib/utils';
import { useIsMobile, useIsTablet } from '@/hooks/useMediaQuery';

interface ResponsiveLayoutProps {
  children: React.ReactNode;
  className?: string;
  mobileClassName?: string;
  tabletClassName?: string;
  desktopClassName?: string;
}

export const ResponsiveLayout: React.FC<ResponsiveLayoutProps> = ({
  children,
  className,
  mobileClassName,
  tabletClassName,
  desktopClassName
}) => {
  const isMobile = useIsMobile();
  const isTablet = useIsTablet();
  
  return (
    <div className={cn(
      className,
      isMobile && mobileClassName,
      isTablet && tabletClassName,
      !isMobile && !isTablet && desktopClassName
    )}>
      {children}
    </div>
  );
};

interface ResponsiveGridProps {
  children: React.ReactNode;
  className?: string;
  cols?: {
    mobile?: number;
    tablet?: number;
    desktop?: number;
  };
  gap?: {
    mobile?: number;
    tablet?: number;
    desktop?: number;
  };
}

export const ResponsiveGrid: React.FC<ResponsiveGridProps> = ({
  children,
  className,
  cols = { mobile: 1, tablet: 2, desktop: 3 },
  gap = { mobile: 4, tablet: 4, desktop: 6 }
}) => {
  const isMobile = useIsMobile();
  const isTablet = useIsTablet();
  
  const getGridCols = () => {
    if (isMobile) return `grid-cols-${cols.mobile}`;
    if (isTablet) return `grid-cols-${cols.tablet}`;
    return `grid-cols-${cols.desktop}`;
  };
  
  const getGap = () => {
    if (isMobile) return `gap-${gap.mobile}`;
    if (isTablet) return `gap-${gap.tablet}`;
    return `gap-${gap.desktop}`;
  };
  
  return (
    <div className={cn(
      'grid',
      getGridCols(),
      getGap(),
      className
    )}>
      {children}
    </div>
  );
};

interface ResponsiveStackProps {
  children: React.ReactNode;
  className?: string;
  direction?: {
    mobile?: 'row' | 'col';
    tablet?: 'row' | 'col';
    desktop?: 'row' | 'col';
  };
  spacing?: {
    mobile?: number;
    tablet?: number;
    desktop?: number;
  };
}

export const ResponsiveStack: React.FC<ResponsiveStackProps> = ({
  children,
  className,
  direction = { mobile: 'col', tablet: 'row', desktop: 'row' },
  spacing = { mobile: 2, tablet: 4, desktop: 4 }
}) => {
  const isMobile = useIsMobile();
  const isTablet = useIsTablet();
  
  const getDirection = () => {
    if (isMobile) return direction.mobile === 'row' ? 'flex-row' : 'flex-col';
    if (isTablet) return direction.tablet === 'row' ? 'flex-row' : 'flex-col';
    return direction.desktop === 'row' ? 'flex-row' : 'flex-col';
  };
  
  const getSpacing = () => {
    if (isMobile) return `gap-${spacing.mobile}`;
    if (isTablet) return `gap-${spacing.tablet}`;
    return `gap-${spacing.desktop}`;
  };
  
  return (
    <div className={cn(
      'flex',
      getDirection(),
      getSpacing(),
      className
    )}>
      {children}
    </div>
  );
};
