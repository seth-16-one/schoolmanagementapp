CREATE TABLE IF NOT EXISTS public.push_devices (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  device_token text NOT NULL UNIQUE,
  platform text,
  app_role text,
  device_name text,
  app_version text,
  is_active boolean NOT NULL DEFAULT true,
  last_seen_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_push_devices_user_active
ON public.push_devices (user_id, is_active, last_seen_at DESC);
