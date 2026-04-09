CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS public.messages (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  room_id text NOT NULL,
  content text NOT NULL,
  sender text NOT NULL,
  created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_room_created_at
ON public.messages(room_id, created_at DESC);

ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "allow read messages" ON public.messages;
CREATE POLICY "allow read messages"
ON public.messages
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "allow insert messages" ON public.messages;
CREATE POLICY "allow insert messages"
ON public.messages
FOR INSERT
TO anon, authenticated
WITH CHECK (true);

ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
