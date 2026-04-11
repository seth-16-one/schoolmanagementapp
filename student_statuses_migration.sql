CREATE TABLE IF NOT EXISTS public.student_statuses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_email text NOT NULL,
  student_name text,
  avatar_url text,
  text_content text,
  media_type text CHECK (media_type IN ('text', 'image', 'video')),
  media_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours'),
  is_deleted boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_student_statuses_email_created
  ON public.student_statuses (student_email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_student_statuses_expires_at
  ON public.student_statuses (expires_at);

ALTER TABLE public.student_statuses ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "read student statuses" ON public.student_statuses;
CREATE POLICY "read student statuses"
ON public.student_statuses
FOR SELECT
USING (expires_at > now() AND is_deleted = false);

DROP POLICY IF EXISTS "insert student statuses" ON public.student_statuses;
CREATE POLICY "insert student statuses"
ON public.student_statuses
FOR INSERT
WITH CHECK (expires_at > now());

DROP POLICY IF EXISTS "update student statuses" ON public.student_statuses;
CREATE POLICY "update student statuses"
ON public.student_statuses
FOR UPDATE
USING (student_email = current_setting('request.jwt.claims', true)::json->>'email');

DROP POLICY IF EXISTS "delete student statuses" ON public.student_statuses;
CREATE POLICY "delete student statuses"
ON public.student_statuses
FOR DELETE
USING (student_email = current_setting('request.jwt.claims', true)::json->>'email');

