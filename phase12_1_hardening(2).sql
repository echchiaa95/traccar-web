-- ============================================================================
-- PHASE 12.1 — PRODUCTION HARDENING
-- SAFETY: purely additive / in-place CREATE OR REPLACE. No DROP, no TRUNCATE,
-- no data deletion. All authorization re-derived server-side from auth.uid().
-- Function signatures kept identical to Phase 12 (same arg/return types) so
-- CREATE OR REPLACE applies cleanly; only bodies change.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. fn_list_permissions_catalog — permission catalog via RPC (no direct
--    table read from the frontend). Staff of a school or superadmin only.
-- ----------------------------------------------------------------------------
create or replace function fn_list_permissions_catalog()
returns table(permission_key text, module text, name text, description text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;

  v_school_id := fn_my_primary_school();
  if not (fn_is_superadmin()
          or (v_school_id is not null and fn_is_school_staff(v_school_id))) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
    select p.permission_key, p.module, p.name, p.description
    from permissions p
    order by p.module, p.permission_key;
end;
$$;
revoke all on function fn_list_permissions_catalog() from public;
grant execute on function fn_list_permissions_catalog() to authenticated;

-- ----------------------------------------------------------------------------
-- 2. fn_update_class(uuid, jsonb) — patch semantics: a key ABSENT from p_data
--    means "no change"; a key PRESENT with JSON null means "clear the value"
--    (this is how removing the class teacher is expressed).
--    Keys: name, level, capacity, teacher_id, is_disabled.
--    New overload — the original scalar-signature fn_update_class stays
--    available unchanged for backward compatibility.
-- ----------------------------------------------------------------------------
create or replace function fn_update_class(p_class_id uuid, p_data jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_name text;
  v_level text;
  v_capacity integer;
  v_teacher_id uuid;
  v_is_disabled boolean;
begin
  if p_data is null or jsonb_typeof(p_data) <> 'object' then
    raise exception 'INVALID_PATCH';
  end if;

  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;
  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_data ? 'name' then
    v_name := nullif(trim(coalesce(p_data->>'name', '')), '');
    if v_name is null then
      raise exception 'CLASS_NAME_REQUIRED';
    end if;
  end if;

  if p_data ? 'level' then
    v_level := nullif(trim(coalesce(p_data->>'level', '')), '');
  end if;

  if p_data ? 'capacity' then
    v_capacity := nullif(p_data->>'capacity', '')::integer;
    if v_capacity is not null and v_capacity <= 0 then
      raise exception 'INVALID_CAPACITY';
    end if;
  end if;

  if p_data ? 'teacher_id' then
    -- explicit JSON null -> clear the teacher; absent key -> no change.
    v_teacher_id := nullif(p_data->>'teacher_id', '')::uuid;
    if v_teacher_id is not null and not exists (
      select 1 from teachers
      where id = v_teacher_id and school_id = v_school_id and deleted_at is null
    ) then
      raise exception 'INVALID_TEACHER';
    end if;
  end if;

  if p_data ? 'is_disabled' then
    v_is_disabled := coalesce((p_data->>'is_disabled')::boolean, false);
  end if;

  update classes set
    name        = case when p_data ? 'name' then v_name else name end,
    level       = case when p_data ? 'level' then v_level else level end,
    capacity    = case when p_data ? 'capacity' then v_capacity else capacity end,
    teacher_id  = case when p_data ? 'teacher_id' then v_teacher_id else teacher_id end,
    is_disabled = case when p_data ? 'is_disabled' then v_is_disabled else is_disabled end
  where id = p_class_id;

  perform fn_safe_audit(v_school_id, 'UPDATE_CLASS', 'classes', p_class_id, null, p_data);
end;
$$;
revoke all on function fn_update_class(uuid, jsonb) from public;
grant execute on function fn_update_class(uuid, jsonb) to authenticated;

-- ----------------------------------------------------------------------------
-- 3. fn_update_academic_year — disabling the CURRENT year is now blocked:
--    the caller must set another year as current first.
-- ----------------------------------------------------------------------------
create or replace function fn_update_academic_year(
  p_year_id uuid,
  p_name text default null,
  p_is_disabled boolean default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_is_current boolean;
begin
  select school_id, is_current into v_school_id, v_is_current
  from academic_years where id = p_year_id;
  if v_school_id is null then
    raise exception 'INVALID_ACADEMIC_YEAR';
  end if;
  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_is_disabled = true and v_is_current then
    raise exception 'YEAR_IS_CURRENT';
  end if;

  if p_name is not null and trim(p_name) <> '' then
    -- Legacy column is "label" (phase2_schema), not "name".
    if exists (select 1 from academic_years
               where school_id = v_school_id and label = trim(p_name) and id <> p_year_id) then
      raise exception 'ACADEMIC_YEAR_EXISTS';
    end if;
    update academic_years set label = trim(p_name) where id = p_year_id;
  end if;

  if p_is_disabled is not null then
    update academic_years set is_disabled = p_is_disabled where id = p_year_id;
  end if;

  perform fn_safe_audit(v_school_id, 'UPDATE_ACADEMIC_YEAR', 'academic_years', p_year_id,
    null, jsonb_build_object('name', p_name, 'is_disabled', p_is_disabled));
end;
$$;

-- ----------------------------------------------------------------------------
-- 4. fn_save_attendance — a TEACHER (not staff, no attendance.manage grant)
--    may only record attendance for a class they actually teach.
-- ----------------------------------------------------------------------------
create or replace function fn_save_attendance(
  p_class_id uuid,
  p_date date,
  p_rows jsonb
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_row jsonb;
  v_count integer := 0;
  v_teacher_id uuid;
  v_class_teacher uuid;
begin
  select school_id, teacher_id into v_school_id, v_class_teacher
  from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;

  select t.id into v_teacher_id
  from teachers t
  where t.school_id = v_school_id
    and t.profile_id = auth.uid()
    and t.deleted_at is null
  limit 1;

  if not (fn_is_school_staff(v_school_id)
          or v_teacher_id is not null
          or fn_has_permission('attendance.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- Teacher without a management grant: own classes only.
  if not fn_is_school_staff(v_school_id)
     and not fn_has_permission('attendance.manage', v_school_id)
     and v_teacher_id is not null
     and (v_class_teacher is null or v_class_teacher <> v_teacher_id) then
    raise exception 'NOT_YOUR_CLASS';
  end if;

  if p_rows is null or jsonb_typeof(p_rows) <> 'array' then
    raise exception 'INVALID_ROWS';
  end if;

  for v_row in select * from jsonb_array_elements(p_rows)
  loop
    -- The student must have an ACTIVE enrollment in THIS class (school
    -- isolation is enforced by following the class -> school chain).
    if not exists (
      select 1 from student_enrollments se
      where se.student_id = (v_row->>'student_id')::uuid
        and se.class_id = p_class_id
        and se.status = 'ACTIVE'
    ) then
      continue;
    end if;

    if coalesce(v_row->>'status', '') not in ('present', 'absent', 'late', 'excused') then
      continue;
    end if;

    insert into attendance_records
      (school_id, student_id, class_id, att_date, status, note, recorded_by)
    values (
      v_school_id,
      (v_row->>'student_id')::uuid,
      p_class_id,
      coalesce(p_date, current_date),
      v_row->>'status',
      nullif(trim(coalesce(v_row->>'note', '')), ''),
      auth.uid()
    )
    on conflict (student_id, class_id, att_date)
    do update set status = excluded.status,
                  note = excluded.note,
                  recorded_by = excluded.recorded_by,
                  updated_at = now();

    v_count := v_count + 1;
  end loop;

  perform fn_safe_audit(v_school_id, 'SAVE_ATTENDANCE', 'attendance_records', p_class_id,
    null, jsonb_build_object('date', coalesce(p_date, current_date), 'count', v_count));

  return v_count;
end;
$$;

-- ----------------------------------------------------------------------------
-- 5. fn_get_class_attendance — same teacher restriction for reading a roster.
--    Return columns unchanged (student_id, full_name, student_number, status,
--    note) so existing callers keep working.
-- ----------------------------------------------------------------------------
create or replace function fn_get_class_attendance(p_class_id uuid, p_date date default null)
returns table(student_id uuid, full_name text, student_number text, status text, note text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_teacher_id uuid;
  v_class_teacher uuid;
begin
  select school_id, teacher_id into v_school_id, v_class_teacher
  from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;

  select t.id into v_teacher_id
  from teachers t
  where t.school_id = v_school_id and t.profile_id = auth.uid() and t.deleted_at is null
  limit 1;

  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('attendance.view', v_school_id)
          or fn_has_permission('attendance.manage', v_school_id)
          or (v_teacher_id is not null and v_class_teacher = v_teacher_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select
    st.id, st.full_name, st.student_number,
    ar.status, ar.note
  from student_enrollments se
  join students st on st.id = se.student_id and st.deleted_at is null
  left join attendance_records ar
    on ar.student_id = st.id and ar.class_id = se.class_id
   and ar.att_date = coalesce(p_date, current_date)
  where se.class_id = p_class_id
    and se.status = 'ACTIVE'
  order by st.full_name;
end;
$$;

-- ----------------------------------------------------------------------------
-- 6. fn_add_grade — teacher restricted to classes they teach; the student's
--    school is always derived from the students row (never from the client),
--    and the class must belong to that same school.
-- ----------------------------------------------------------------------------
create or replace function fn_add_grade(
  p_student_id uuid,
  p_class_id uuid,
  p_subject_id uuid,
  p_period text,
  p_grade_type text,
  p_score numeric,
  p_max_score numeric default 20,
  p_note text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_id uuid;
  v_teacher_id uuid;
  v_class_id uuid;
  v_class_teacher uuid;
  v_class_school uuid;
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;

  select t.id into v_teacher_id
  from teachers t
  where t.school_id = v_school_id and t.profile_id = auth.uid() and t.deleted_at is null
  limit 1;

  if not (fn_is_school_staff(v_school_id) or v_teacher_id is not null
          or fn_has_permission('grades.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- Resolve the class used for the ownership check: explicit class,
  -- otherwise the student's ACTIVE enrollment class.
  v_class_id := p_class_id;
  if v_class_id is null then
    select se.class_id into v_class_id
    from student_enrollments se
    where se.student_id = p_student_id and se.status = 'ACTIVE'
    limit 1;
  end if;

  if v_class_id is not null then
    select c.teacher_id, c.school_id into v_class_teacher, v_class_school
    from classes c where c.id = v_class_id;
    if v_class_school is null or v_class_school <> v_school_id then
      raise exception 'INVALID_CLASS';
    end if;
  end if;

  -- Teacher without a management grant: own classes only.
  if not fn_is_school_staff(v_school_id)
     and not fn_has_permission('grades.manage', v_school_id)
     and v_teacher_id is not null
     and (v_class_teacher is null or v_class_teacher <> v_teacher_id) then
    raise exception 'NOT_YOUR_CLASS';
  end if;

  -- Legacy NOT NULL columns (subject_id, score, grade_date) never get NULL:
  if p_subject_id is null then
    raise exception 'GRADE_SUBJECT_REQUIRED';
  end if;
  if not exists (select 1 from subjects s
                 where s.id = p_subject_id and s.school_id = v_school_id) then
    raise exception 'INVALID_SUBJECT';
  end if;
  if p_score is null or p_score < 0 then
    raise exception 'INVALID_SCORE';
  end if;

  -- teacher_id references teachers(id) (legacy FK): store the caller's
  -- teachers row (resolved above from profile_id = auth.uid()), never
  -- auth.uid() itself. grade_date filled explicitly (legacy column).
  insert into student_grades
    (school_id, student_id, class_id, subject_id, period, grade_type, score, max_score, note, grade_date, teacher_id)
  values (
    v_school_id, p_student_id, v_class_id, p_subject_id,
    nullif(trim(coalesce(p_period, '')), ''),
    nullif(trim(coalesce(p_grade_type, '')), 'تقويم'),
    p_score, coalesce(p_max_score, 20),
    nullif(trim(coalesce(p_note, '')), ''),
    current_date,
    v_teacher_id
  )
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'ADD_GRADE', 'student_grades', v_id,
    null, jsonb_build_object('student_id', p_student_id, 'score', p_score));

  return v_id;
end;
$$;

-- ============================================================================
-- END OF PHASE 12.1
-- ============================================================================
