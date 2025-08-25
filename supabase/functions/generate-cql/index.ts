import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface CQLGenerationRequest {
  description: string;
  model?: string;
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
    const { description, model = 'gpt-5-2025-08-07', context } = body;

    if (!description?.trim()) {
      return new Response(JSON.stringify({ error: 'Description is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log(`Generating CQL query for: ${description} (model: ${model})`);

    const systemPrompt = `You are an expert in CrowdStrike Falcon LogScale (Humio) and CQL (Common Query Language). 

Your task is to:
1. AUTOMATICALLY determine the appropriate query type(s) needed from the user's natural language description
2. Build comprehensive, production-ready CQL queries that fulfill the complete request
3. Combine multiple query types if needed (search + aggregation, joins, etc.)
4. Include proper visualization hints when requested (maps, charts, tables)

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
- Visualization: | stats count() as total | table(), | chart(), | map()

COMMON PATTERNS:
- Process events: event_simpleName=ProcessRollup2
- Network events: event_simpleName=NetworkConnect*
- File events: event_simpleName=*FileWrite*
- DNS events: event_simpleName=DnsRequest
- Authentication: event_simpleName=UserLogon*
- PowerShell: event_simpleName=ProcessRollup2 AND ImageFileName=*powershell*
- Azure logs: sourcetype="azure:*"
- Risk levels: riskScore, riskLevel (1-5, where 3+ is medium-critical)

AUTO-DETECTION RULES:
- "search for/find" → Search query with filters
- "count/how many/statistics" → Search + aggregation
- "map/geographical/location" → Search + aggregation + geographical grouping
- "correlate/join/match" → Multi-query joins
- "monitor/alert/detect" → Alert-style continuous queries
- "trend/over time/timeline" → Time-based aggregations with bucketing

VISUALIZATION HINTS:
- Map format: Include geographic fields (country, region, ip) in groupBy
- Chart format: Use bucket() for time series, groupBy for categories  
- Table format: Use | table field1, field2, field3
- Statistics: Use | stats count(), sum(), avg() etc.

Build complete, executable queries that fulfill the entire user request. Include comments for complex logic.

Generate ONLY the CQL query code without explanations or markdown formatting.`;

    const userPrompt = `Analyze this request and build a comprehensive CQL query: ${description}

Additional context: ${context || 'Standard CrowdStrike Falcon environment'}

Automatically determine what type of query is needed and build a complete solution. Return only the CQL query code.`;

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${openAIApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: model,
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
    
    // Log the full response for debugging
    console.log('OpenAI response data:', JSON.stringify(data, null, 2));
    
    // Check if we have choices and content
    if (!data.choices || !data.choices[0] || !data.choices[0].message) {
      console.error('Invalid OpenAI response structure:', data);
      return new Response(JSON.stringify({ error: 'Invalid response from AI model' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    
    const generatedQuery = data.choices[0].message.content?.trim() || '';
    
    // Log the actual generated content
    console.log('Generated query content:', generatedQuery);
    
    if (!generatedQuery) {
      console.error('Empty query generated by AI model');
      return new Response(JSON.stringify({ error: 'AI model returned empty query. Please try again with different wording.' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('CQL query generated successfully');

    return new Response(JSON.stringify({ 
      query: generatedQuery,
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