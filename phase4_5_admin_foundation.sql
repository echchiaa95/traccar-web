-- ============================================================================
-- Phase 4.5 — Admin Foundation
-- Provides fn_admin_update_student for school admins to update student records.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.fn_admin_update_student(
  p_student_id UUID,
  p_school_id UUID,
  p_full_name TEXT DEFAULT NULL,
  p_date_of_birth DATE DEFAULT NULL,
  p_gender TEXT DEFAULT NULL,
  p_address TEXT DEFAULT NULL,
  p_parent_phone TEXT DEFAULT NULL,
  p_parent_email TEXT DEFAULT NULL,
  p_emergency_contact_name TEXT DEFAULT NULL,
  p_emergency_contact_phone TEXT DEFAULT NULL,
  p_medical_notes TEXT DEFAULT NULL,
  p_updated_by UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_existing_school UUID;
  v_result JSONB;
BEGIN
  -- Verify student belongs to the school
  SELECT school_id INTO v_existing_school
  FROM students
  WHERE id = p_student_id AND deleted_at IS NULL;

  IF v_existing_school IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Student not found');
  END IF;

  IF v_existing_school != p_school_id THEN
    RETURN jsonb_build_object('ok', false, 'error', 'School mismatch');
  END IF;

  -- Update student
  UPDATE students SET
    full_name = COALESCE(p_full_name, full_name),
    date_of_birth = COALESCE(p_date_of_birth, date_of_birth),
    gender = COALESCE(p_gender, gender),
    address = COALESCE(p_address, address),
    parent_phone = COALESCE(p_parent_phone, parent_phone),
    parent_email = COALESCE(p_parent_email, parent_email),
    emergency_contact_name = COALESCE(p_emergency_contact_name, emergency_contact_name),
    emergency_contact_phone = COALESCE(p_emergency_contact_phone, emergency_contact_phone),
    medical_notes = COALESCE(p_medical_notes, medical_notes),
    updated_at = NOW()
  WHERE id = p_student_id;

  -- Audit log
  INSERT INTO activity_logs (school_id, actor_profile_id, action, target_type, target_id, details)
  VALUES (p_school_id, p_updated_by, 'UPDATE_STUDENT', 'student', p_student_id,
          jsonb_build_object('updated_by', p_updated_by));

  RETURN jsonb_build_object('ok', true);
END;
$$;

COMMENT ON FUNCTION public.fn_admin_update_student IS 'Allows school admin to update a student record. Enforces school isolation.';
