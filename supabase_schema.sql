-- Setup the table for storing calculations
CREATE TABLE IF NOT EXISTS public.calculations (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  data jsonb NOT NULL,
  created_at timestamp with time zone DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.calculations ENABLE ROW LEVEL SECURITY;

-- Tylko zalogowani użytkownicy mogą dodawać własne kalkulacje
CREATE POLICY "Authenticated insert own" ON public.calculations
  FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = user_id);

-- Użytkownicy widzą tylko własne kalkulacje
CREATE POLICY "Read own calculations" ON public.calculations
  FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

-- Użytkownicy mogą usuwać tylko własne kalkulacje
CREATE POLICY "Delete own calculations" ON public.calculations
  FOR DELETE TO authenticated
  USING (auth.uid() = user_id);

-- Automatyczne czyszczenie starych rekordów (opcjonalne, wymaga pg_cron w Supabase)
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('delete-old-calculations', '0 0 * * *', $$
--   DELETE FROM public.calculations WHERE created_at < now() - interval '7 days';
-- $$);
