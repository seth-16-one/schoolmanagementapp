CREATE TABLE IF NOT EXISTS public.admin_warnings (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  admin_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  target_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  message_id uuid REFERENCES public.messages(id) ON DELETE SET NULL,
  reason text NOT NULL,
  status text DEFAULT 'active',
  created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS admin_warnings_target_idx
ON public.admin_warnings (target_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS admin_warnings_message_idx
ON public.admin_warnings (message_id);

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS moderation_status text DEFAULT 'clear',
ADD COLUMN IF NOT EXISTS moderation_reason text,
ADD COLUMN IF NOT EXISTS flagged_at timestamp without time zone;

CREATE INDEX IF NOT EXISTS messages_moderation_idx
ON public.messages (moderation_status, flagged_at DESC);

CREATE TABLE IF NOT EXISTS public.notifications (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  title text NOT NULL,
  message text NOT NULL,
  type text DEFAULT 'general',
  is_read boolean DEFAULT false,
  created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS notifications_user_read_idx
ON public.notifications (user_id, is_read, created_at DESC);
