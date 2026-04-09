create table if not exists public.login_sessions (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  role text,
  ip_address text,
  device_info text,
  suspicious boolean not null default false,
  is_current boolean not null default true,
  logged_in_at timestamp without time zone not null default current_timestamp,
  logged_out_at timestamp without time zone
);

create index if not exists login_sessions_user_logged_in_idx
on public.login_sessions (user_id, logged_in_at desc);

create index if not exists login_sessions_user_current_idx
on public.login_sessions (user_id, is_current);
