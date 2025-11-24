import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { gunzip } from 'https://deno.land/x/compress@v0.4.5/gzip/mod.ts';

// Supabase client, akan menggunakan variabel lingkungan dari Supabase
const supabaseAdmin = createClient(
  Deno.env.get('SUPABASE_URL') ?? '',
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
);

interface LogEntry {
  WorkerName?: string;
  ResponseBodySize?: number;
}

serve(async (req) => {
  try {
    const payload = await req.json();
    const record = payload.record;

    if (payload.type !== 'INSERT' || !record) {
      return new Response('Not a new file event. Skipping.', { status: 200 });
    }

    const bucketId = record.bucket_id;
    const filePath = record.name;

    console.log(`Processing file: ${filePath} from bucket: ${bucketId}`);

    const { data: fileData, error: fileError } = await supabaseAdmin.storage
      .from(bucketId)
      .download(filePath);

    if (fileError) throw fileError;

    const compressedData = await fileData.arrayBuffer();
    const decompressedData = gunzip(new Uint8Array(compressedData));
    const logText = new TextDecoder().decode(decompressedData);

    const stats = new Map<string, { requests: number; bandwidth: number }>();
    const logEntries = logText.trim().split('
');

    for (const line of logEntries) {
      if (!line) continue;
      const log: LogEntry = JSON.parse(line);
      const workerName = log.WorkerName;
      const bandwidth = log.ResponseBodySize || 0;

      if (workerName) {
        const current = stats.get(workerName) || { requests: 0, bandwidth: 0 };
        current.requests += 1;
        current.bandwidth += bandwidth;
        stats.set(workerName, current);
      }
    }

    for (const [workerName, data] of stats.entries()) {
      const { error: rpcError } = await supabaseAdmin.rpc('increment_worker_stats', {
        worker_name_in: workerName,
        req_inc: data.requests,
        bw_inc: data.bandwidth,
      });
      if (rpcError) {
        console.error(`Error updating stats for ${workerName}:`, rpcError);
      }
    }

    console.log(`Successfully processed stats for ${stats.size} workers.`);

    const { error: deleteError } = await supabaseAdmin.storage
      .from(bucketId)
      .remove([filePath]);

    if (deleteError) throw deleteError;

    console.log(`Successfully deleted file: ${filePath}`);

    return new Response(JSON.stringify({ message: 'Log processed successfully' }), {
      headers: { 'Content-Type': 'application/json' },
      status: 200,
    });

  } catch (error) {
    console.error('An error occurred:', error.message);
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { 'Content-Type': 'application/json' },
      status: 500,
    });
  }
});
