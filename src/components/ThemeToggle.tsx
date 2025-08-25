import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Monitor, Zap } from 'lucide-react';
import { initializeTheme, setTheme, type Theme } from '@/lib/theme';

export const ThemeToggle = () => {
  const [currentTheme, setCurrentTheme] = useState<Theme>('analyst');

  useEffect(() => {
    const theme = initializeTheme();
    setCurrentTheme(theme);
  }, []);

  const toggleTheme = () => {
    const newTheme = currentTheme === 'analyst' ? 'pipboy' : 'analyst';
    setTheme(newTheme);
    setCurrentTheme(newTheme);
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={toggleTheme}
      className="gap-2"
    >
      {currentTheme === 'analyst' ? (
        <>
          <Monitor className="h-4 w-4" />
          Analyst
        </>
      ) : (
        <>
          <Zap className="h-4 w-4 text-glow" />
          Pip-Boy
        </>
      )}
    </Button>
  );
};