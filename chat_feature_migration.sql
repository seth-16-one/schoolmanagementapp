ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS message_type text NOT NULL DEFAULT 'text';

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS media_url text;

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS thumbnail_url text;

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS duration_seconds integer;

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS delivered_at timestamp without time zone;

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS read_at timestamp without time zone;

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS client_message_id text;

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS group_id uuid;

CREATE TABLE IF NOT EXISTS public.chat_groups (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  created_by uuid REFERENCES public.users(id),
  avatar_url text,
  created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS public.chat_group_members (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  group_id uuid NOT NULL REFERENCES public.chat_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  is_admin boolean DEFAULT false,
  role text DEFAULT 'member',
  joined_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (group_id, user_id)
);

ALTER TABLE public.chat_group_members
ADD COLUMN IF NOT EXISTS role text DEFAULT 'member';

UPDATE public.chat_group_members
SET role = CASE WHEN is_admin = true THEN 'admin' ELSE 'member' END
WHERE role IS NULL OR role = '';

CREATE INDEX IF NOT EXISTS idx_chat_group_members_group_role
ON public.chat_group_members(group_id, role);

CREATE TABLE IF NOT EXISTS public.blocked_users (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  blocker_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  blocked_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS blocked_users_pair_uidx
ON public.blocked_users (blocker_user_id, blocked_user_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'messages_group_id_fkey'
  ) THEN
    ALTER TABLE public.messages
    ADD CONSTRAINT messages_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES public.chat_groups(id)
    ON DELETE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_messages_group_id ON public.messages(group_id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver_created
ON public.messages(sender_id, receiver_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_friend_requests_sender_receiver
ON public.friend_requests(sender_id, receiver_id, created_at DESC);

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS reply_to_message_id uuid REFERENCES public.messages(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS forwarded_from_message_id uuid REFERENCES public.messages(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS is_pinned boolean DEFAULT false,
ADD COLUMN IF NOT EXISTS pinned_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS reactions jsonb DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_messages_reply_to_message_id
ON public.messages(reply_to_message_id);

CREATE INDEX IF NOT EXISTS idx_messages_pinned_at
ON public.messages(is_pinned, pinned_at DESC);
