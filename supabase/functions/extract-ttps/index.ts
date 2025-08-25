import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface TTpExtractionRequest {
  text: string;
  model?: string; // allow client override; will default to a broadly available model
}

interface TTP {
  technique_id: string;
  subtechnique_id?: string;
  tactic?: string;
  behavior: string;
  evidence_excerpt: string;
}

interface Detection {
  title: string;
  description: string;
  data_sources: string[];
  suggested_query_snippets: string[];
}

interface ExtractedEntities {
  products: string[];
  operating_systems: string[];
  cloud_providers: string[];
  identities: string[];
  tools: string[];
  malware: string[];
}

interface TTpExtractionResponse {
  summary: string;
  ttps: TTP[];
  detections: Detection[];
  entities: ExtractedEntities;
  model_used: string;
  processing_time_ms: number;
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

  const startTime = Date.now();
  const openAIApiKey = Deno.env.get('OPENAI_API_KEY');

  if (!openAIApiKey) {
    console.error('OPENAI_API_KEY not configured');
    return new Response(JSON.stringify({ error: 'OpenAI API key not configured' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const { text, model = 'gpt-4o-mini' }: TTpExtractionRequest = await req.json();

    if (!text?.trim()) {
      return new Response(JSON.stringify({ error: 'Text is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Size limit: 50KB
    if (text.length > 50000) {
      return new Response(JSON.stringify({ error: 'Text too large (max 50KB)' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    let currentModel = model || 'gpt-4o-mini';
    console.log(`Processing TTP extraction with model: ${currentModel}, text length: ${text.length}`);

    const systemPrompt = `You are a cybersecurity analyst specialized in extracting TTPs (Tactics, Techniques, and Procedures) from threat intelligence reports. 

Extract and structure the following information from the provided text:

1. **Summary**: A concise 2-3 sentence summary of the threat/campaign
2. **TTPs**: Map behaviors to MITRE ATT&CK framework with:
   - technique_id (e.g., "T1055")
   - subtechnique_id (if applicable, e.g., "T1055.001")
   - tactic (e.g., "Defense Evasion")
   - behavior (clear description of what the adversary does)
   - evidence_excerpt (exact quote from text supporting this TTP)

3. **Detections**: Actionable detection ideas with:
   - title (detection name)
   - description (what to look for)
   - data_sources (e.g., ["Process monitoring", "Network traffic", "File monitoring"])
   - suggested_query_snippets (generic detection logic, not vendor-specific)

4. **Entities**: Extract mentioned:
   - products (software/services targeted or used)
   - operating_systems
   - cloud_providers
   - identities (usernames, emails, etc.)
   - tools (legitimate or malicious)
   - malware (families, variants)

Return ONLY valid JSON with this exact structure:
{
  "summary": "string",
  "ttps": [{"technique_id": "string", "subtechnique_id": "string|null", "tactic": "string", "behavior": "string", "evidence_excerpt": "string"}],
  "detections": [{"title": "string", "description": "string", "data_sources": ["string"], "suggested_query_snippets": ["string"]}],
  "entities": {
    "products": ["string"],
    "operating_systems": ["string"], 
    "cloud_providers": ["string"],
    "identities": ["string"],
    "tools": ["string"],
    "malware": ["string"]
  }
}

Focus on accuracy over quantity. Only include TTPs with strong evidence.`;

    const makeBody = (m: string) => {
      const body: any = {
        model: m,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: text }
        ],
        response_format: { type: 'json_object' }
      };
      if (m.startsWith('gpt-5') || m.startsWith('o3') || m.startsWith('o4')) {
        body.max_completion_tokens = 4000;
      } else {
        body.max_tokens = 4000;
        body.temperature = 0.3;
      }
      return body;
    };

    const callOpenAI = async (m: string) => {
      console.log(`Calling OpenAI API with model ${m}...`);
      const resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${openAIApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(makeBody(m)),
      });
      return resp;
    };

    // First attempt
    let response = await callOpenAI(currentModel);

    // Fallback on model access errors
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`OpenAI API error (${response.status}) for model ${currentModel}:`, errorText);
      const isModelAccessError = errorText.includes('model_not_found') || errorText.includes('does not have access to model');
      if (isModelAccessError && currentModel !== 'gpt-4o-mini') {
        currentModel = 'gpt-4o-mini';
        console.log('Retrying with fallback model gpt-4o-mini...');
        response = await callOpenAI(currentModel);
      }
      if (!response.ok) {
        const finalText = await response.text();
        console.error(`OpenAI API error (${response.status}) after fallback:`, finalText);
        return new Response(JSON.stringify({ 
          error: `OpenAI API error: ${response.status}`,
          details: finalText,
          tried_models: [model, currentModel].filter(Boolean)
        }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    const data = await response.json();
    console.log('OpenAI response received, parsing...');

    let extractedData;
    try {
      extractedData = JSON.parse(data.choices[0].message.content);
    } catch (parseError) {
      console.error('Failed to parse OpenAI JSON response:', parseError);
      console.error('Raw content:', data.choices[0].message.content);
      return new Response(JSON.stringify({ 
        error: 'Invalid JSON response from AI model',
        details: data.choices[0].message.content 
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const processingTime = Date.now() - startTime;
    console.log(`TTP extraction completed in ${processingTime}ms`);

    const result: TTpExtractionResponse = {
      summary: extractedData.summary || '',
      ttps: extractedData.ttps || [],
      detections: extractedData.detections || [],
      entities: extractedData.entities || {
        products: [],
        operating_systems: [],
        cloud_providers: [],
        identities: [],
        tools: [],
        malware: []
      },
      model_used: currentModel,
      processing_time_ms: processingTime
    };

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in extract-ttps function:', error);
    const processingTime = Date.now() - startTime;
    
    return new Response(JSON.stringify({ 
      error: 'Internal server error',
      details: error.message,
      processing_time_ms: processingTime
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});