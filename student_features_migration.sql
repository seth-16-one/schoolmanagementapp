CREATE TABLE IF NOT EXISTS public.assignments (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  title text NOT NULL,
  description text,
  subject_id uuid REFERENCES public.subjects(id),
  teacher_id uuid REFERENCES public.teachers(id),
  class_name text,
  attachment_url text,
  youtube_url text,
  assigned_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
  due_date timestamp without time zone,
  status text DEFAULT 'published'
);

CREATE TABLE IF NOT EXISTS public.assignment_submissions (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  assignment_id uuid NOT NULL REFERENCES public.assignments(id) ON DELETE CASCADE,
  student_id uuid NOT NULL REFERENCES public.students(id) ON DELETE CASCADE,
  submission_text text,
  submission_file_url text,
  submitted_at timestamp without time zone,
  status text DEFAULT 'pending',
  score numeric,
  feedback text,
  is_late boolean DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS assignment_submission_student_uidx
ON public.assignment_submissions (assignment_id, student_id);

CREATE INDEX IF NOT EXISTS assignments_class_due_idx
ON public.assignments (class_name, due_date, assigned_at);

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

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS moderation_status text DEFAULT 'clear',
ADD COLUMN IF NOT EXISTS moderation_reason text,
ADD COLUMN IF NOT EXISTS flagged_at timestamp without time zone;

CREATE INDEX IF NOT EXISTS messages_receiver_read_idx
ON public.messages (receiver_id, is_read, created_at DESC);

CREATE INDEX IF NOT EXISTS messages_group_created_idx
ON public.messages (group_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS chat_group_members_group_user_uidx
ON public.chat_group_members (group_id, user_id);

CREATE UNIQUE INDEX IF NOT EXISTS friend_requests_sender_receiver_uidx
ON public.friend_requests (sender_id, receiver_id);

CREATE UNIQUE INDEX IF NOT EXISTS parent_child_parent_student_uidx
ON public.parent_child (parent_id, student_id);

CREATE SEQUENCE IF NOT EXISTS public.student_admission_number_seq
START WITH 11000
INCREMENT BY 1
MINVALUE 11000;

SELECT setval(
  'public.student_admission_number_seq',
  GREATEST(
    COALESCE(
      (SELECT MAX(admission_number::bigint)
       FROM public.students
       WHERE admission_number ~ '^[0-9]+$'),
      10999
    ),
    10999
  ),
  true
);

ALTER TABLE public.students
ALTER COLUMN admission_number SET DEFAULT nextval('public.student_admission_number_seq')::text;

UPDATE public.students
SET admission_number = nextval('public.student_admission_number_seq')::text
WHERE admission_number IS NULL OR btrim(admission_number) = '';
