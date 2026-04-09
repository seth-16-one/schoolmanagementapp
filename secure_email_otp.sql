CREATE TABLE IF NOT EXISTS public.email_otp_challenges (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  purpose text NOT NULL DEFAULT 'general',
  otp_hash text NOT NULL,
  request_ip text,
  user_agent text,
  attempt_count integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 5,
  expires_at timestamp without time zone NOT NULL,
  verified_at timestamp without time zone,
  consumed_at timestamp without time zone,
  last_attempt_at timestamp without time zone,
  created_at timestamp without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_email_purpose_created
ON public.email_otp_challenges(email, purpose, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_email_otp_challenges_expires
ON public.email_otp_challenges(expires_at);
