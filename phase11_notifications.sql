-- ============================================================================
-- Phase 11 — Notifications System
-- Additive migration. No DROP. No TRUNCATE.
-- ============================================================================

-- Notifications table
CREATE TABLE IF NOT EXISTS public.notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  school_id UUID NOT NULL REFERENCES public.schools(id) ON DELETE CASCADE,
  profile_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT,
  type TEXT NOT NULL DEFAULT 'general' CHECK (type IN ('general', 'alert', 'attendance', 'payment', 'transport', 'grade')),
  read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE public.notifications IS 'User notifications with school isolation';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_notifications_school_profile ON public.notifications(school_id, profile_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON public.notifications(school_id, profile_id, read) WHERE read = false;
CREATE INDEX IF NOT EXISTS idx_notifications_created ON public.notifications(created_at DESC);

-- RLS
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notifications_select_own ON public.notifications;
CREATE POLICY notifications_select_own ON public.notifications
  FOR SELECT USING (profile_id = auth.uid());

DROP POLICY IF EXISTS notifications_insert_system ON public.notifications;
CREATE POLICY notifications_insert_system ON public.notifications
  FOR INSERT WITH CHECK (school_id IN (SELECT school_id FROM profiles WHERE id = auth.uid()));

DROP POLICY IF EXISTS notifications_update_own ON public.notifications;
CREATE POLICY notifications_update_own ON public.notifications
  FOR UPDATE USING (profile_id = auth.uid());

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION public.fn_update_notifications_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_notifications_updated ON public.notifications;
CREATE TRIGGER trg_notifications_updated
  BEFORE UPDATE ON public.notifications
  FOR EACH ROW EXECUTE FUNCTION public.fn_update_notifications_timestamp();

-- RPC: send_notification (for backend/system use)
CREATE OR REPLACE FUNCTION public.fn_send_notification(
  p_school_id UUID,
  p_profile_id UUID,
  p_title TEXT,
  p_body TEXT DEFAULT NULL,
  p_type TEXT DEFAULT 'general'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_notif_id UUID;
BEGIN
  INSERT INTO notifications (school_id, profile_id, title, body, type)
  VALUES (p_school_id, p_profile_id, p_title, p_body, p_type)
  RETURNING id INTO v_notif_id;

  RETURN jsonb_build_object('ok', true, 'id', v_notif_id);
END;
$$;
