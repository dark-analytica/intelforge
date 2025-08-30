// CORS Configuration for Supabase Edge Functions
import { isValidOrigin } from '../../src/lib/env-config.ts';

export function corsHeaders(origin?: string): Record<string, string> {
  const allowedOrigin = origin && isValidOrigin(origin) ? origin : 'null';
  
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

export function handleCors(req: Request): Response | null {
  if (req.method === 'OPTIONS') {
    return new Response('ok', {
      headers: corsHeaders(req.headers.get('Origin') || undefined)
    });
  }
  return null;
}
