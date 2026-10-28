// DoNotEncode.ai v0.6 — Supabase Edge Function (AI Agent Visit Tracker & Live Audit API)
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'X-Aegis-Shield': 'v0.6-SOVEREIGN',
};

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  const url = new URL(req.url);
  const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
  const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? Deno.env.get('SUPABASE_ANON_KEY') ?? '';
  const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

  // Detect live ChatGPT / Perplexity / Claude / Gemini visits or buyer clicks
  const ua = req.headers.get('user-agent') || '';
  const referer = req.headers.get('referer') || '';

  if (req.method === 'POST' && url.pathname.endsWith('/simulate-ai-visit')) {
    const body = await req.json().catch(() => ({}));
    const engine = ['chatgpt', 'perplexity', 'claude', 'gemini'].includes(body.engine) ? body.engine : 'chatgpt';
    const visitType = body.type === 'buyer_click' ? 'buyer_click' : 'prompt_lookup';
    const pagePath = typeof body.page === 'string' ? body.page : '/products/featured';

    const row = {
      engine,
      visit_type: visitType,
      badge: visitType === 'buyer_click' ? 'BUYER CLICKED LINK' : 'LIVE RECOMMENDATION',
      event_plain:
        visitType === 'buyer_click'
          ? `A customer clicked your recommended product link inside ${engine.toUpperCase()} and arrived on your store`
          : `Someone asked ${engine.toUpperCase()} for a recommendation — it read your product & pricing summary live`,
      signal: visitType === 'buyer_click' ? `Referer: https://${engine}.com/` : `User-Agent: ${engine}-User/1.0`,
      page_path: pagePath,
    };

    if (supabase) {
      await supabase.from('ai_agent_visits').insert([row]);
    }

    return new Response(JSON.stringify({ ok: true, version: '0.6.0', event: row }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  if (supabase) {
    const { data: recent } = await supabase
      .from('ai_agent_visits')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(10);

    return new Response(
      JSON.stringify({
        ok: true,
        version: '0.6.0',
        detectedUserAgent: ua.slice(0, 80),
        detectedReferer: referer.slice(0, 80),
        recentVisits: recent ?? [],
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }

  return new Response(
    JSON.stringify({ ok: true, version: '0.6.0', message: 'DoNotEncode.ai v0.6 Supabase Edge Function Active' }),
    { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
  );
});
