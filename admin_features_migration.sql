CREATE TABLE IF NOT EXISTS public.admin_warnings (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  admin_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  target_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  message_id uuid REFERENCES public.messages(id) ON DELETE SET NULL,
  reason text NOT NULL,
  status text DEFAULT 'active',
  appeal_message text,
  appeal_status text DEFAULT 'pending',
  appeal_submitted_at timestamp without time zone,
  appeal_deadline_at timestamp without time zone,
  resolved_at timestamp without time zone,
  resolution_note text,
  created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.admin_warnings
ADD COLUMN IF NOT EXISTS appeal_message text,
ADD COLUMN IF NOT EXISTS appeal_status text DEFAULT 'pending',
ADD COLUMN IF NOT EXISTS appeal_submitted_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS appeal_deadline_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS freeze_duration_hours integer,
ADD COLUMN IF NOT EXISTS freeze_until timestamp without time zone,
ADD COLUMN IF NOT EXISTS resolved_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS resolution_note text;

CREATE INDEX IF NOT EXISTS admin_warnings_target_idx
ON public.admin_warnings (target_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS admin_warnings_message_idx
ON public.admin_warnings (message_id);

ALTER TABLE public.messages
ADD COLUMN IF NOT EXISTS moderation_status text DEFAULT 'clear',
ADD COLUMN IF NOT EXISTS moderation_reason text,
ADD COLUMN IF NOT EXISTS flagged_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS reviewed_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS reviewed_by uuid REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS is_chat_frozen boolean DEFAULT false,
ADD COLUMN IF NOT EXISTS chat_frozen_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS chat_freeze_reason text,
ADD COLUMN IF NOT EXISTS chat_freeze_expires_at timestamp without time zone;

ALTER TABLE public.teachers
ADD COLUMN IF NOT EXISTS profile_locked boolean DEFAULT true;

ALTER TABLE public.students
ADD COLUMN IF NOT EXISTS profile_locked boolean DEFAULT false,
ADD COLUMN IF NOT EXISTS profile_picture_url text;

ALTER TABLE public.teachers
ADD COLUMN IF NOT EXISTS profile_picture_url text;

UPDATE public.students
SET profile_locked = COALESCE(profile_locked, false)
WHERE profile_locked IS NULL;

UPDATE public.teachers
SET profile_locked = COALESCE(profile_locked, true)
WHERE profile_locked IS NULL;

CREATE INDEX IF NOT EXISTS messages_moderation_idx
ON public.messages (moderation_status, flagged_at DESC);

CREATE TABLE IF NOT EXISTS public.notifications (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  title text NOT NULL,
  message text NOT NULL,
  type text DEFAULT 'general',
  sender_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  sender_role text,
  audience text DEFAULT 'direct',
  is_read boolean DEFAULT false,
  created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE public.notifications
ADD COLUMN IF NOT EXISTS sender_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS sender_role text,
ADD COLUMN IF NOT EXISTS audience text DEFAULT 'direct';

CREATE INDEX IF NOT EXISTS notifications_user_read_idx
ON public.notifications (user_id, is_read, created_at DESC);

ALTER TABLE public.announcements
ADD COLUMN IF NOT EXISTS announcement_type text DEFAULT 'activity',
ADD COLUMN IF NOT EXISTS expires_after_view boolean DEFAULT false,
ADD COLUMN IF NOT EXISTS expiry_days integer,
ADD COLUMN IF NOT EXISTS expires_at timestamp without time zone,
ADD COLUMN IF NOT EXISTS audience_role text DEFAULT 'all',
ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES public.users(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS public.announcement_views (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  announcement_id uuid NOT NULL REFERENCES public.announcements(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  viewed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
  expires_at timestamp without time zone
);

CREATE UNIQUE INDEX IF NOT EXISTS announcement_views_announcement_user_uidx
ON public.announcement_views (announcement_id, user_id);

CREATE INDEX IF NOT EXISTS announcements_type_created_idx
ON public.announcements (announcement_type, created_at DESC);
