ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS authenticator_secret text,
ADD COLUMN IF NOT EXISTS authenticator_enabled boolean NOT NULL DEFAULT false;
