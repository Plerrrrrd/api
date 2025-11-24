import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';

const supabaseAdmin = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
);

serve(async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;

  const authToken = req.headers.get('Authorization');
  if (authToken !== `Bearer ${Deno.env.get('CRON_SECRET')}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  try {
    if (path.endsWith('/daily')) {
      const { error } = await supabaseAdmin
        .from('worker_stats')
        .update({ daily_requests: 0 })
        .gt('daily_requests', 0);

      if (error) throw error;
      console.log('Daily stats reset successfully.');
      return new Response('Daily stats reset', { status: 200 });

    } else if (path.endsWith('/monthly')) {
      const { error } = await supabaseAdmin
        .from('worker_stats')
        .update({ 
          monthly_requests: 0,
          monthly_bandwidth: 0 
        })
        .gt('monthly_requests', 0);

      if (error) throw error;
      console.log('Monthly stats reset successfully.');
      return new Response('Monthly stats reset', { status: 200 });

    } else {
      return new Response('Not found. Use /daily or /monthly endpoints.', { status: 404 });
    }
  } catch (error) {
    console.error('Error resetting stats:', error.message);
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { 'Content-Type': 'application/json' },
      status: 500,
    });
  }
});
