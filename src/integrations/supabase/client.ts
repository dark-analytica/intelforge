import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';
import { getEnvironmentConfig, getSecurityHeaders } from '../../lib/env-config';

// Get secure environment configuration
const config = getEnvironmentConfig();

// Import the supabase client like this:
// import { supabase } from "@/integrations/supabase/client";

export const supabase = createClient<Database>(
  config.supabase.url,
  config.supabase.anonKey,
  {
    auth: {
      storage: localStorage,
      persistSession: true,
      autoRefreshToken: true,
    },
    global: {
      headers: {
        ...getSecurityHeaders(),
        'X-Client-Info': 'cqlforge-client'
      }
    },
    db: {
      schema: 'public'
    }
  }
);