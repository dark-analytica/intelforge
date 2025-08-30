// Environment Configuration with Security Best Practices
interface EnvironmentConfig {
  supabase: {
    url: string;
    anonKey: string;
  };
  development: boolean;
  allowedOrigins: string[];
}

// Validate environment variables
function validateEnvVar(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

// Get environment configuration with validation
export function getEnvironmentConfig(): EnvironmentConfig {
  // Use environment variables if available, otherwise fall back to build-time values
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://your-project.supabase.co';
  const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || 'your-anon-key';
  
  // In production, these should come from environment variables
  if (import.meta.env.PROD) {
    validateEnvVar('VITE_SUPABASE_URL', import.meta.env.VITE_SUPABASE_URL);
    validateEnvVar('VITE_SUPABASE_ANON_KEY', import.meta.env.VITE_SUPABASE_ANON_KEY);
  }

  return {
    supabase: {
      url: supabaseUrl,
      anonKey: supabaseAnonKey
    },
    development: import.meta.env.DEV,
    allowedOrigins: [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://your-domain.com' // Replace with actual production domain
    ]
  };
}

// Security headers for API requests
export function getSecurityHeaders(): Record<string, string> {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  };
}

// Validate origin for CORS
export function isValidOrigin(origin: string): boolean {
  const config = getEnvironmentConfig();
  return config.allowedOrigins.includes(origin) || config.development;
}
