-- ============================================================================
-- Phase 8 — SuperAdmin Platform
-- SuperAdmin-only functions for platform management.
-- No SuperAdmin creation from frontend.
-- ============================================================================

-- Ensure is_superadmin() helper exists
CREATE OR REPLACE FUNCTION public.is_superadmin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles
    WHERE id = auth.uid()
      AND role = 'superadmin'
      AND deleted_at IS NULL
  );
$$;

-- fn_list_all_schools: SuperAdmin only
CREATE OR REPLACE FUNCTION public.fn_list_all_schools()
RETURNS TABLE (
  id UUID,
  name TEXT,
  address TEXT,
  phone TEXT,
  email TEXT,
  admin_count BIGINT,
  student_count BIGINT,
  created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT public.is_superadmin() THEN
    RAISE EXCEPTION 'SuperAdmin only';
  END IF;

  RETURN QUERY
  SELECT
    s.id,
    s.name,
    s.address,
    s.phone,
    s.email,
    (SELECT COUNT(*) FROM profiles p WHERE p.school_id = s.id AND p.role = 'admin' AND p.deleted_at IS NULL)::BIGINT,
    (SELECT COUNT(*) FROM students st WHERE st.school_id = s.id AND st.deleted_at IS NULL)::BIGINT,
    s.created_at
  FROM schools s
  WHERE s.deleted_at IS NULL
  ORDER BY s.created_at DESC;
END;
$$;

-- fn_create_school: SuperAdmin only
CREATE OR REPLACE FUNCTION public.fn_create_school(
  p_name TEXT,
  p_address TEXT DEFAULT NULL,
  p_phone TEXT DEFAULT NULL,
  p_email TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_school_id UUID;
BEGIN
  IF NOT public.is_superadmin() THEN
    RETURN jsonb_build_object('ok', false, 'error', 'SuperAdmin only');
  END IF;

  IF p_name IS NULL OR LENGTH(TRIM(p_name)) = 0 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'School name is required');
  END IF;

  INSERT INTO schools (name, address, phone, email)
  VALUES (TRIM(p_name), p_address, p_phone, p_email)
  RETURNING id INTO v_school_id;

  INSERT INTO activity_logs (school_id, actor_profile_id, action, target_type, target_id, details)
  VALUES (v_school_id, auth.uid(), 'CREATE_SCHOOL', 'school', v_school_id,
          jsonb_build_object('name', p_name));

  RETURN jsonb_build_object('ok', true, 'school_id', v_school_id);
END;
$$;

-- fn_list_school_admins: SuperAdmin only
CREATE OR REPLACE FUNCTION public.fn_list_school_admins(p_school_id UUID)
RETURNS TABLE (
  id UUID,
  full_name TEXT,
  email TEXT,
  role TEXT,
  is_active BOOLEAN,
  created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT public.is_superadmin() THEN
    RAISE EXCEPTION 'SuperAdmin only';
  END IF;

  RETURN QUERY
  SELECT
    p.id,
    p.full_name,
    u.email,
    p.role,
    p.is_active,
    p.created_at
  FROM profiles p
  JOIN auth.users u ON u.id = p.id
  WHERE p.school_id = p_school_id
    AND p.role = 'admin'
    AND p.deleted_at IS NULL
  ORDER BY p.created_at DESC;
END;
$$;

-- fn_get_platform_stats: SuperAdmin only
CREATE OR REPLACE FUNCTION public.fn_get_platform_stats()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_school_count BIGINT;
  v_student_count BIGINT;
  v_staff_count BIGINT;
  v_guard_check_count BIGINT;
BEGIN
  IF NOT public.is_superadmin() THEN
    RETURN jsonb_build_object('ok', false, 'error', 'SuperAdmin only');
  END IF;

  SELECT COUNT(*) INTO v_school_count FROM schools WHERE deleted_at IS NULL;
  SELECT COUNT(*) INTO v_student_count FROM students WHERE deleted_at IS NULL;
  SELECT COUNT(*) INTO v_staff_count FROM profiles WHERE deleted_at IS NULL AND role != 'student';
  SELECT COUNT(*) INTO v_guard_check_count FROM guard_checks;

  RETURN jsonb_build_object(
    'ok', true,
    'schools', v_school_count,
    'students', v_student_count,
    'staff', v_staff_count,
    'guard_checks', v_guard_check_count
  );
END;
$$;
