create table if not exists public.app_versions (
  id bigserial primary key,
  app_name text not null default 'eschool',
  flavor text not null,
  platform text not null default 'android',
  version text not null,
  build_number integer not null,
  apk_url text not null,
  release_notes text,
  is_forced boolean not null default false,
  is_enabled boolean not null default true,
  created_at timestamp without time zone not null default current_timestamp,
  updated_at timestamp without time zone not null default current_timestamp
);

create index if not exists app_versions_lookup_idx
on public.app_versions (app_name, flavor, is_enabled, build_number desc, created_at desc);

alter table public.app_versions
enable row level security;

drop policy if exists "public can read enabled app versions" on public.app_versions;
create policy "public can read enabled app versions"
on public.app_versions
for select
to anon, authenticated
using (is_enabled = true);
