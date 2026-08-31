-- ============================================================================
-- supabase/migrations/phase4_2_1_security_hardening.sql
-- PHASE 4.2.1 — SECURITY HARDENING
--
-- SAFETY GUARANTEE: every statement is CREATE OR REPLACE FUNCTION on
-- functions introduced in phase4_2_permissions_system.sql (same
-- signatures — no DROP needed, existing GRANTs are preserved by Postgres
-- across CREATE OR REPLACE). No table, RLS policy, or Authentication file/
-- function is touched. fn_register_student / fn_issue_badge /
-- fn_reissue_badge / fn_suspend_badge remain completely unmodified.
--
-- WHAT THIS FIXES (see audit in the delivery message for full detail):
--   1. CRITICAL: fn_guard_issue_badge / fn_guard_reissue_badge /
--      fn_guard_suspend_badge / fn_guard_register_student used
--      `if v_role not in (...) and not fn_has_permission(...) then raise`.
--      When v_role was NULL (caller has NO role at all in the target
--      school — exactly the cross-school attack in TEST 8), `NULL NOT IN
--      (...)` evaluates to NULL, the IF's guard condition never becomes
--      TRUE, and the privileged action proceeded UNGUARDED. Fixed by an
--      explicit `if v_role is null then raise` check before anything else.
--   2. fn_guard_register_student resolved school_id via
--      `... where profile_id = auth.uid() limit 1` with NO school filter
--      at all — nondeterministic if the caller holds roles in more than
--      one school. Fixed: school_id is now derived from the CLASS being
--      targeted (unambiguous — a class belongs to exactly one school),
--      with an added check that the academic year belongs to that same
--      school (fn_register_student itself trusts both values as given).
--   3. All role lookups now go through fn_resolve_my_role(), which orders
--      deterministically by privilege (admin > director > guard > ...)
--      instead of an unordered LIMIT 1 — closes the same class of bug
--      everywhere at once, including a profile holding two roles in the
--      SAME school.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 0. fn_resolve_my_role — new helper, single source of deterministic role
--    resolution for a given school. Used by every function below instead
--    of each repeating its own ad-hoc (and previously ambiguous) lookup.
-- ----------------------------------------------------------------------------
create or replace function fn_resolve_my_role(p_school_id uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role::text from user_roles
  where profile_id = auth.uid() and school_id = p_school_id
  order by case role::text
    when 'superadmin' then 0
    when 'admin'      then 1
    when 'director'   then 2
    when 'guard'      then 3
    when 'teacher'    then 4
    when 'driver'     then 5
    when 'parent'     then 6
    else 7
  end
  limit 1;
$$;
revoke all on function fn_resolve_my_role(uuid) from public;
grant execute on function fn_resolve_my_role(uuid) to authenticated;

-- ----------------------------------------------------------------------------
-- 1. fn_has_permission — same signature/behavior, now via fn_resolve_my_role.
-- ----------------------------------------------------------------------------
create or replace function fn_has_permission(p_permission_key text, p_school_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role text;
begin
  if exists (select 1 from user_roles where profile_id = auth.uid() and role::text = 'superadmin') then
    return true;
  end if;

  v_role := fn_resolve_my_role(p_school_id);

  if v_role in ('admin','director') then
    return true;
  end if;

  if v_role = 'guard' then
    return exists (
      select 1 from guard_permissions gp
      join permissions p on p.id = gp.permission_id
      where gp.profile_id = auth.uid() and gp.school_id = p_school_id and p.permission_key = p_permission_key
    );
  end if;

  return false; -- covers v_role IS NULL and any other role — fail closed
end;
$$;
revoke all on function fn_has_permission(text, uuid) from public;
grant execute on function fn_has_permission(text, uuid) to authenticated;

-- ----------------------------------------------------------------------------
-- 2. fn_get_my_permissions — same signature/behavior, now via fn_resolve_my_role.
-- ----------------------------------------------------------------------------
create or replace function fn_get_my_permissions(p_school_id uuid)
returns table(permission_key text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role text;
begin
  if exists (select 1 from user_roles where profile_id = auth.uid() and role::text = 'superadmin') then
    return query select p.permission_key from permissions p;
    return;
  end if;

  v_role := fn_resolve_my_role(p_school_id);

  if v_role in ('admin','director') then
    return query select p.permission_key from permissions p;
  elsif v_role = 'guard' then
    return query
      select p.permission_key from guard_permissions gp
      join permissions p on p.id = gp.permission_id
      where gp.profile_id = auth.uid() and gp.school_id = p_school_id;
  end if;
  return; -- v_role IS NULL or any other role -> empty set, fail closed
end;
$$;
revoke all on function fn_get_my_permissions(uuid) from public;
grant execute on function fn_get_my_permissions(uuid) to authenticated;

-- ----------------------------------------------------------------------------
-- 3. fn_guard_register_student — CRITICAL FIX: explicit NULL-role denial,
--    school_id derived from the class (not an ambiguous blind lookup),
--    and academic_year/school consistency check added before ever calling
--    the untouched fn_register_student.
-- ----------------------------------------------------------------------------
create or replace function fn_guard_register_student(
  p_full_name text, p_student_number text, p_class_id uuid, p_academic_year_id uuid,
  p_birth_date date default null, p_gender text default null
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_school_id uuid;
  v_role text;
begin
  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;

  if not exists (
    select 1 from academic_years where id = p_academic_year_id and school_id = v_school_id
  ) then
    raise exception 'ACADEMIC_YEAR_SCHOOL_MISMATCH';
  end if;

  v_role := fn_resolve_my_role(v_school_id);
  if v_role is null then
    raise exception 'PERMISSION_DENIED: no role in this school';
  end if;
  if v_role not in ('admin','director') and not fn_has_permission('students.create', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.create';
  end if;

  return fn_register_student(v_school_id, p_full_name, p_student_number, p_class_id, p_academic_year_id, p_birth_date, p_gender);
end;
$$;
revoke all on function fn_guard_register_student(text, text, uuid, uuid, date, text) from public;
grant execute on function fn_guard_register_student(text, text, uuid, uuid, date, text) to authenticated;

-- ----------------------------------------------------------------------------
-- 4. fn_guard_issue_badge — CRITICAL FIX: explicit NULL-role denial.
-- ----------------------------------------------------------------------------
create or replace function fn_guard_issue_badge(p_student_id uuid)
returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_school_id uuid;
  v_role text;
begin
  v_school_id := fn_student_school(p_student_id);
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;
  v_role := fn_resolve_my_role(v_school_id);
  if v_role is null then
    raise exception 'PERMISSION_DENIED: no role in this school';
  end if;
  if v_role not in ('admin','director') and not fn_has_permission('students.badge.issue', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.badge.issue';
  end if;
  return fn_issue_badge(p_student_id);
end;
$$;
revoke all on function fn_guard_issue_badge(uuid) from public;
grant execute on function fn_guard_issue_badge(uuid) to authenticated;

-- ----------------------------------------------------------------------------
-- 5. fn_guard_reissue_badge — CRITICAL FIX: explicit NULL-role denial.
-- ----------------------------------------------------------------------------
create or replace function fn_guard_reissue_badge(p_student_id uuid, p_reason text default null)
returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_school_id uuid;
  v_role text;
begin
  v_school_id := fn_student_school(p_student_id);
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;
  v_role := fn_resolve_my_role(v_school_id);
  if v_role is null then
    raise exception 'PERMISSION_DENIED: no role in this school';
  end if;
  if v_role not in ('admin','director') and not fn_has_permission('students.badge.reissue', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.badge.reissue';
  end if;
  return fn_reissue_badge(p_student_id, p_reason);
end;
$$;
revoke all on function fn_guard_reissue_badge(uuid, text) from public;
grant execute on function fn_guard_reissue_badge(uuid, text) to authenticated;

-- ----------------------------------------------------------------------------
-- 6. fn_guard_suspend_badge — CRITICAL FIX: explicit NULL-role denial.
-- ----------------------------------------------------------------------------
create or replace function fn_guard_suspend_badge(p_badge_id uuid, p_new_status badge_status, p_reason text default null)
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_student_id uuid;
  v_school_id uuid;
  v_role text;
begin
  select student_id into v_student_id from student_badges where id = p_badge_id;
  v_school_id := fn_student_school(v_student_id);
  if v_school_id is null then
    raise exception 'INVALID_BADGE';
  end if;
  v_role := fn_resolve_my_role(v_school_id);
  if v_role is null then
    raise exception 'PERMISSION_DENIED: no role in this school';
  end if;
  if v_role not in ('admin','director') and not fn_has_permission('students.badge.suspend', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.badge.suspend';
  end if;
  perform fn_suspend_badge(p_badge_id, p_new_status, p_reason);
end;
$$;
revoke all on function fn_guard_suspend_badge(uuid, badge_status, text) from public;
grant execute on function fn_guard_suspend_badge(uuid, badge_status, text) to authenticated;

-- ============================================================================
-- END OF PHASE 4.2.1 — no INSERT/UPDATE/DELETE on any data anywhere in this
-- file. GUARD001's existing guard_permissions rows (seeded in Phase 4.2)
-- are untouched — this file contains no DELETE/TRUNCATE on that table.
-- ============================================================================
