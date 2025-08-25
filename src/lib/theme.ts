export type Theme = 'analyst' | 'pipboy';

export const getTheme = (): Theme => {
  if (typeof window === 'undefined') return 'analyst';
  return (localStorage.getItem('cqlintel-theme') as Theme) || 'analyst';
};

export const setTheme = (theme: Theme) => {
  localStorage.setItem('cqlintel-theme', theme);
  document.documentElement.className = theme === 'pipboy' ? 'theme-pipboy' : '';
};

export const initializeTheme = () => {
  const theme = getTheme();
  setTheme(theme);
  return theme;
};