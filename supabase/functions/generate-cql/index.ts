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
- Environment: Enterprise security monitoring with multi-vendor integrations
- Focus on: Security events, logs, and threat hunting across all supported integrations

CQL SYNTAX REFERENCE:
- Basic search: field=value, field!=value, field~"regex"
- Logical operators: AND, OR, NOT
- Functions: count(), groupBy(), stats(), sort(), limit(), top(), distinct()
- Time: @timestamp, bucket(), now(), relative times (-1d, -1h, -24h)
- Aggregations: sum(), avg(), min(), max(), count(), distinct()
- String functions: match(), contains(), startsWith(), endsWith(), regex()
- Network: cidr(), ip(), geoip()
- Geographic: country(), region(), city(), latitude(), longitude()
- Field extraction: eval, coalesce(), case(), if()
- Visualization: | stats | table(), | chart(), | worldmap(), | geostats()

SUPPORTED INTEGRATIONS & PATTERNS:

MICROSOFT/AZURE:
- Azure logs: sourcetype="azure:*" OR index="azure_*" OR source="azure"
- Azure AD: sourcetype="azure:aad:*" OR EventName="SigninLogs" OR logSource="AzureAD"
- Office 365: sourcetype="o365:*" OR workload="Exchange" OR workload="SharePoint"
- Windows: sourcetype="windows:*" OR EventLog="Security" OR Channel="Security"

AWS:
- CloudTrail: sourcetype="aws:cloudtrail" OR eventSource="*.amazonaws.com"
- VPC Flow: sourcetype="aws:vpc:flowlogs" OR logType="VPC_FLOW_LOGS"
- GuardDuty: sourcetype="aws:guardduty" OR type="GuardDuty"

GOOGLE CLOUD:
- Audit logs: sourcetype="gcp:*" OR logName="projects/*/logs/cloudaudit*"
- Security: sourcetype="gcp:security" OR resource.type="gce_instance"

NETWORK SECURITY:
- Cisco: sourcetype="cisco:*" OR vendor="Cisco"
- Palo Alto: sourcetype="pan:*" OR vendor="PaloAlto"
- Fortinet: sourcetype="fortigate:*" OR vendor="Fortinet"
- Check Point: sourcetype="checkpoint:*" OR vendor="CheckPoint"
- F5: sourcetype="f5:*" OR vendor="F5"

IDENTITY & ACCESS:
- Okta: sourcetype="okta:*" OR app="okta"
- Ping Identity: sourcetype="ping:*" OR source="ping"
- CyberArk: sourcetype="cyberark:*" OR vendor="CyberArk"
- One Identity: sourcetype="oneidentity:*" OR vendor="OneIdentity"

ENDPOINT SECURITY:
- CrowdStrike: event_simpleName=* OR sourcetype="crowdstrike:*"
- Trellix: sourcetype="trellix:*" OR vendor="Trellix"
- Broadcom/Symantec: sourcetype="symantec:*" OR vendor="Broadcom"

CLOUD SECURITY:
- Netskope: sourcetype="netskope:*" OR vendor="Netskope"
- Zscaler: sourcetype="zscaler:*" OR vendor="Zscaler"
- Cloudflare: sourcetype="cloudflare:*" OR vendor="Cloudflare"

EMAIL SECURITY:
- Proofpoint: sourcetype="proofpoint:*" OR vendor="Proofpoint"
- Mimecast: sourcetype="mimecast:*" OR vendor="Mimecast"

WEB INFRASTRUCTURE:
- Apache: sourcetype="apache:*" OR server="apache"
- Nginx: sourcetype="nginx:*" OR server="nginx"
- HAProxy: sourcetype="haproxy:*" OR server="haproxy"

IOT/OT SECURITY:
- Claroty: sourcetype="claroty:*" OR vendor="Claroty"
- Nozomi: sourcetype="nozomi:*" OR vendor="Nozomi"
- Dragos: sourcetype="dragos:*" OR vendor="Dragos"

RISK LEVEL STANDARDIZATION:
- Numeric: riskLevel >= 3 OR RiskScore >= 3 OR risk_score >= 3
- Text: riskLevel IN ["Medium", "High", "Critical"] OR severity IN ["medium", "high", "critical"]
- Combined: (riskLevel >= 3 OR RiskScore >= 3 OR severity IN ["medium", "high", "critical"])

GEOGRAPHIC FIELD MAPPING:
- IP-based: country(IPAddress), city(IPAddress), geoip(src_ip)
- Native fields: Country, Region, City, country_code, region_name
- Coordinates: latitude(location), longitude(location)

AUTO-DETECTION RULES:
- "search for/find" → Search query with proper integration filters
- "count/how many/statistics" → Search + aggregation with meaningful grouping
- "map/geographical/location/display in map format" → Geographic visualization with proper coordinate extraction
- "correlate/join/match" → Multi-source correlation with proper field mapping
- "monitor/alert/detect" → Alert-style queries with thresholds and conditions
- "trend/over time/timeline" → Time-based aggregations with appropriate bucketing

COMPREHENSIVE QUERY BUILDING EXAMPLES:

Geographic Authentication Query:
sourcetype="azure:*" AND (EventName="SigninLogs" OR event_simpleName=UserLogon*) 
AND (riskLevel >= 3 OR RiskScore >= 3) 
AND @timestamp >= now()-24h
| eval geo_country = coalesce(country(IPAddress), Country, "Unknown")
| eval geo_city = coalesce(city(IPAddress), City, "Unknown") 
| stats count() as auth_events, distinct(UserPrincipalName) as unique_users by geo_country, geo_city
| where auth_events > 0
| sort -auth_events
| worldmap lat=latitude(geo_city) lon=longitude(geo_city) count=auth_events

Multi-Vendor Network Security:
(sourcetype="pan:*" OR sourcetype="cisco:*" OR sourcetype="fortigate:*")
AND (action="blocked" OR action="denied" OR disposition="blocked")
AND @timestamp >= now()-1h
| eval vendor = case(
    match(sourcetype, "pan:*"), "Palo Alto",
    match(sourcetype, "cisco:*"), "Cisco", 
    match(sourcetype, "fortigate:*"), "Fortinet",
    "Unknown"
)
| stats count() as blocked_events by vendor, src_ip, dest_port
| sort -blocked_events

Cloud Multi-Provider Query:
(sourcetype="aws:*" OR sourcetype="azure:*" OR sourcetype="gcp:*")
AND (eventName="ConsoleLogin" OR EventName="SigninLogs" OR protoPayload.methodName="SetIamPolicy")
AND @timestamp >= now()-24h
| eval cloud_provider = case(
    match(sourcetype, "aws:*"), "AWS",
    match(sourcetype, "azure:*"), "Azure",
    match(sourcetype, "gcp:*"), "GCP",
    "Unknown"
)
| stats count() as events, distinct(userIdentity.userName) as unique_users by cloud_provider
| chart timechart(span=1h) by cloud_provider

BEST PRACTICES:
- Always include time boundaries for performance
- Use coalesce() for field standardization across vendors
- Include proper error handling with case() functions
- Add meaningful field aliases for readability
- Use appropriate visualization based on data type
- Include vendor detection for multi-source queries
- Standardize risk/severity fields across integrations

Build complete, executable queries that fulfill the entire user request with proper integration awareness.

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