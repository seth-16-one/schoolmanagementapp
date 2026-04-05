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
  joined_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (group_id, user_id)
);

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
