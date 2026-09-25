import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || 'https://lofljkxtgdhvdfijstfs.supabase.co';
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxvZmxqa3h0Z2RodmRmaWpzdGZzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODcyNDAxNTksImV4cCI6MjEwMjgxNjE1OX0.esbMpI3ukTecXQJtCKZW3avotmyj1FgtYKhsB97fKJg';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Direct Supabase Query Helpers
export const fetchSupabaseAlerts = async (limit = 20) => {
  const { data, error } = await supabase
    .from('alerts')
    .select('*, detection:detections(*)')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data;
};

export const fetchSupabaseDetections = async (limit = 50) => {
  const { data, error } = await supabase
    .from('detections')
    .select('*')
    .order('timestamp', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return data;
};

export const fetchSupabaseModels = async () => {
  const { data, error } = await supabase
    .from('models')
    .select('*')
    .order('id', { ascending: true });
  if (error) throw error;
  return data;
};

export const fetchSupabaseDatasets = async () => {
  const { data, error } = await supabase
    .from('datasets')
    .select('*')
    .order('uploaded_at', { ascending: false });
  if (error) throw error;
  return data;
};

// Supabase Realtime Subscriptions
export const subscribeToAlerts = (onNewAlert) => {
  const channel = supabase
    .channel('realtime_alerts')
    .on(
      'postgres_changes',
      { event: 'INSERT', schema: 'public', table: 'alerts' },
      (payload) => {
        if (onNewAlert) onNewAlert(payload.new);
      }
    )
    .subscribe();

  return () => {
    supabase.removeChannel(channel);
  };
};

export const subscribeToDetections = (onNewDetection) => {
  const channel = supabase
    .channel('realtime_detections')
    .on(
      'postgres_changes',
      { event: 'INSERT', schema: 'public', table: 'detections' },
      (payload) => {
        if (onNewDetection) onNewDetection(payload.new);
      }
    )
    .subscribe();

  return () => {
    supabase.removeChannel(channel);
  };
};

export default supabase;
