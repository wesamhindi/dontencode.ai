-- DoNotEncode.ai v0.6 — Supabase Schema for Live AI Agent Visit & Product Recommendation Tracking
create table if not exists public.ai_agent_visits (
  id uuid primary key default gen_random_uuid(),
  engine text not null check (engine in ('chatgpt', 'perplexity', 'claude', 'gemini')),
  visit_type text not null check (visit_type in ('prompt_lookup', 'buyer_click', 'index_crawl')),
  badge text not null,
  event_plain text not null,
  signal text not null,
  page_path text not null default '/',
  created_at timestamptz not null default now()
);

create index if not exists idx_ai_agent_visits_created_at on public.ai_agent_visits (created_at desc);
create index if not exists idx_ai_agent_visits_engine on public.ai_agent_visits (engine);

alter table public.ai_agent_visits enable row level security;

create policy "Allow public read of AI agent visits"
  on public.ai_agent_visits
  for select
  to anon, authenticated
  using (true);

create policy "Allow edge insert of AI agent visits"
  on public.ai_agent_visits
  for insert
  to anon, authenticated, service_role
  with check (true);
