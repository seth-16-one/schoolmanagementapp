CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS public.realtime_conversations (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  type text NOT NULL CHECK (type IN ('direct', 'group')),
  title text,
  description text,
  avatar_url text,
  created_by text NOT NULL,
  created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS public.realtime_conversation_members (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  conversation_id uuid NOT NULL REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
  user_id text NOT NULL,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
  joined_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_read_message_id uuid,
  UNIQUE(conversation_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.realtime_messages (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  conversation_id uuid NOT NULL REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
  sender_id text NOT NULL,
  content text NOT NULL,
  group_id uuid REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'delivered', 'seen')),
  delivered_at timestamp without time zone,
  seen_at timestamp without time zone,
  created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS public.realtime_typing_status (
  conversation_id uuid NOT NULL REFERENCES public.realtime_conversations(id) ON DELETE CASCADE,
  user_id text NOT NULL,
  is_typing boolean NOT NULL DEFAULT false,
  expires_at timestamp without time zone NOT NULL,
  updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.realtime_presence (
  user_id text PRIMARY KEY,
  is_online boolean NOT NULL DEFAULT false,
  last_seen_at timestamp without time zone,
  updated_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_realtime_messages_conversation_created
ON public.realtime_messages(conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_realtime_messages_group_created
ON public.realtime_messages(group_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_realtime_members_user_conversation
ON public.realtime_conversation_members(user_id, conversation_id);

CREATE INDEX IF NOT EXISTS idx_realtime_typing_expires
ON public.realtime_typing_status(expires_at);

ALTER TABLE public.realtime_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.realtime_typing_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.realtime_presence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.realtime_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.realtime_conversation_members ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "realtime read messages" ON public.realtime_messages;
CREATE POLICY "realtime read messages"
ON public.realtime_messages
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "realtime insert messages" ON public.realtime_messages;
CREATE POLICY "realtime insert messages"
ON public.realtime_messages
FOR INSERT
TO anon, authenticated
WITH CHECK (true);

DROP POLICY IF EXISTS "realtime update messages" ON public.realtime_messages;
CREATE POLICY "realtime update messages"
ON public.realtime_messages
FOR UPDATE
TO anon, authenticated
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS "realtime read typing" ON public.realtime_typing_status;
CREATE POLICY "realtime read typing"
ON public.realtime_typing_status
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "realtime write typing" ON public.realtime_typing_status;
CREATE POLICY "realtime write typing"
ON public.realtime_typing_status
FOR ALL
TO anon, authenticated
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS "realtime read presence" ON public.realtime_presence;
CREATE POLICY "realtime read presence"
ON public.realtime_presence
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "realtime write presence" ON public.realtime_presence;
CREATE POLICY "realtime write presence"
ON public.realtime_presence
FOR ALL
TO anon, authenticated
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS "realtime read conversations" ON public.realtime_conversations;
CREATE POLICY "realtime read conversations"
ON public.realtime_conversations
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "realtime write conversations" ON public.realtime_conversations;
CREATE POLICY "realtime write conversations"
ON public.realtime_conversations
FOR ALL
TO anon, authenticated
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS "realtime read members" ON public.realtime_conversation_members;
CREATE POLICY "realtime read members"
ON public.realtime_conversation_members
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "realtime write members" ON public.realtime_conversation_members;
CREATE POLICY "realtime write members"
ON public.realtime_conversation_members
FOR ALL
TO anon, authenticated
USING (true)
WITH CHECK (true);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'realtime_messages'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.realtime_messages;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'realtime_typing_status'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.realtime_typing_status;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'realtime_presence'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.realtime_presence;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'realtime_conversations'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.realtime_conversations;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'realtime_conversation_members'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.realtime_conversation_members;
  END IF;
END $$;
