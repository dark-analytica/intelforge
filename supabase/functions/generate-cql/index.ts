import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface CQLGenerationRequest {
  description: string;
  queryType: string;
  context?: string;
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const openAIApiKey = Deno.env.get('OPENAI_API_KEY');
  if (!openAIApiKey) {
    console.error('OPENAI_API_KEY not found in environment variables');
    return new Response(JSON.stringify({ error: 'OpenAI API key not configured' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const body: CQLGenerationRequest = await req.json();
    const { description, queryType, context } = body;

    if (!description?.trim()) {
      return new Response(JSON.stringify({ error: 'Description is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log(`Generating CQL query for: ${description} (type: ${queryType})`);

    const systemPrompt = `You are an expert in CrowdStrike Falcon LogScale (Humio) and CQL (Common Query Language). Generate precise, efficient CQL queries based on user descriptions.

CONTEXT:
- Platform: CrowdStrike Falcon LogScale (Humio)
- Query Language: CQL (Common Query Language)
- Environment: Enterprise security monitoring
- Focus on: Security events, logs, and threat hunting

CQL SYNTAX REFERENCE:
- Basic search: field=value, field!=value, field~"regex"
- Logical operators: AND, OR, NOT
- Functions: count(), groupBy(), stats(), sort(), limit()
- Time: @timestamp, bucket(), now(), relative times (-1d, -1h)
- Aggregations: sum(), avg(), min(), max(), count()
- String functions: match(), contains(), startsWith(), endsWith()
- Network: cidr(), ip()
- File operations: file.*, process.*

COMMON PATTERNS:
- Process events: event_simpleName=ProcessRollup2
- Network events: event_simpleName=NetworkConnect*
- File events: event_simpleName=*FileWrite*
- DNS events: event_simpleName=DnsRequest
- Authentication: event_simpleName=UserLogon*
- PowerShell: event_simpleName=ProcessRollup2 AND ImageFileName=*powershell*

QUERY TYPES:
1. search: Basic filtering and searching
2. aggregation: Counting, grouping, statistics
3. join: Correlating multiple data sources
4. alert: Detection rules and monitoring

BEST PRACTICES:
- Always include time bounds when possible
- Use specific field names from CrowdStrike schema
- Optimize for performance with proper filtering
- Include comments for complex queries
- Use proper escaping for special characters

Generate ONLY the CQL query code without explanations or markdown formatting.`;

    const userPrompt = `Generate a ${queryType} CQL query for: ${description}

Additional context: ${context || 'Standard CrowdStrike Falcon environment'}

Return only the CQL query code.`;

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${openAIApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-5-2025-08-07',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        max_completion_tokens: 1000,
      }),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error(`OpenAI API error (${response.status}):`, errorData);
      return new Response(JSON.stringify({ error: 'Failed to generate CQL query' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const data = await response.json();
    const generatedQuery = data.choices[0].message.content.trim();

    console.log('CQL query generated successfully');

    return new Response(JSON.stringify({ 
      query: generatedQuery,
      queryType,
      description 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in generate-cql function:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});