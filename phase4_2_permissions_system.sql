-- ============================================================================
-- supabase/migrations/phase4_2_permissions_system.sql
-- PHASE 4.2 — REAL PERMISSION SYSTEM + SUPERADMIN SUPPORT
--
-- SAFETY GUARANTEE: every statement in this file is additive.
-- No DROP TABLE, DROP COLUMN, DROP FUNCTION, DELETE, or TRUNCATE anywhere.
-- No existing table, function, or RLS policy is altered.
-- fn_register_student / fn_issue_badge / fn_reissue_badge / fn_suspend_badge
-- are NOT modified — new fn_guard_* wrapper functions call them unchanged.
-- Authentication (index.html, modules/auth.js, modules/supabase.js,
-- login-with-pin, fn_verify_login, fn_set_user_pin) is NOT touched.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. SUPERADMIN enum value (future-proofing only — no SuperAdmin account or
--    UI is created this phase, per Phase 4.2's explicit boundary).
--    NOTE: user_roles.school_id remains NOT NULL. A real SuperAdmin account
--    (not tied to one institution) will need that constraint loosened —
--    deferred until a SuperAdmin account is actually requested, to avoid
--    an unnecessary schema change today. Every function below reads role
--    via `role::text` comparisons (never `'superadmin'::app_role` casts),
--    so nothing here depends on this value being usable within this same
--    transaction (a genuine PostgreSQL restriction on new enum values).
-- ----------------------------------------------------------------------------
alter type app_role add value if not exists 'superadmin';

-- ----------------------------------------------------------------------------
-- 2. permissions — catalog of grantable permission keys.
-- ----------------------------------------------------------------------------
create table permissions (
  id uuid primary key default gen_random_uuid(),
  permission_key text not null unique,
  module text not null,
  name text not null,
  description text,
  created_at timestamptz not null default now()
);

alter table permissions enable row level security;
-- Read-only catalog: any authenticated user may see WHICH permission keys
-- exist (needed later for an Admin UI rendering checkboxes) — no write
-- policy is granted to any client role; only migrations seed this table.
create policy p_permissions_read on permissions for select using (auth.uid() is not null);

insert into permissions (permission_key, module, name) values
  ('students.view',          'students',   'عرض التلاميذ'),
  ('students.create',        'students',   'إضافة تلميذ'),
  ('students.update',        'students',   'تعديل تلميذ'),
  ('students.badge.view',    'students',   'عرض البادج'),
  ('students.badge.issue',   'students',   'إصدار بادج'),
  ('students.badge.reissue', 'students',   'إعادة إصدار بادج'),
  ('students.badge.suspend', 'students',   'تعليق بادج'),
  ('attendance.view',        'attendance', 'عرض الحضور'),
  ('attendance.manage',      'attendance', 'إدارة الحضور'),
  ('classes.view',           'classes',    'عرض الأقسام'),
  ('classes.manage',         'classes',    'إدارة الأقسام'),
  ('teachers.view',          'teachers',   'عرض الأساتذة'),
  ('teachers.create',        'teachers',   'إضافة أستاذ'),
  ('teachers.update',        'teachers',   'تعديل أستاذ'),
  ('drivers.view',           'drivers',    'عرض السائقين'),
  ('drivers.create',         'drivers',    'إضافة سائق'),
  ('drivers.update',         'drivers',    'تعديل سائق'),
  ('parents.view',           'parents',    'عرض أولياء الأمور'),
  ('parents.create',         'parents',    'إضافة ولي أمر'),
  ('parents.update',         'parents',    'تعديل ولي أمر'),
  ('transport.view',         'transport',  'عرض النقل'),
  ('transport.manage',       'transport',  'إدارة النقل'),
  ('payments.view',          'payments',   'عرض المدفوعات'),
  ('payments.manage',        'payments',   'إدارة المدفوعات'),
  ('audit.view',             'audit',      'عرض السجل')
on conflict (permission_key) do nothing;

-- ----------------------------------------------------------------------------
-- 3. guard_permissions — grants a specific permission to a specific guard
--    within a specific school. Admin has full authority by ROLE (per the
--    stated hierarchy: Admin manages the whole institution) and is never
--    represented as rows here — only guard-level grants live in this table.
-- ----------------------------------------------------------------------------
create table guard_permissions (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  permission_id uuid not null references permissions(id) on delete cascade,
  school_id uuid not null references schools(id) on delete cascade,
  granted_by uuid not null references profiles(id),
  created_at timestamptz not null default now(),
  unique (profile_id, permission_id, school_id)
);
create index ix_guard_permissions_profile_school on guard_permissions(profile_id, school_id);

alter table guard_permissions enable row level security;

-- SELECT: a guard sees their own grants; admin/director see all grants for
-- their own school.
create policy p_guard_permissions_self on guard_permissions for select using (profile_id = auth.uid());
create policy p_guard_permissions_staff on guard_permissions for select using (
  fn_has_role(school_id, array['admin','director']::app_role[])
);

-- INSERT/DELETE: admin/director of THAT school only, must record themselves
-- as granted_by (never another admin's identity), and the target profile
-- must actually hold the 'guard' role in that exact school — prevents
-- granting permissions to an arbitrary profile or to an admin/teacher/etc.
create policy p_guard_permissions_insert on guard_permissions for insert with check (
  fn_has_role(school_id, array['admin','director']::app_role[])
  and granted_by = auth.uid()
  and exists (
    select 1 from user_roles ur
    where ur.profile_id = guard_permissions.profile_id
      and ur.school_id = guard_permissions.school_id
      and ur.role = 'guard'
  )
);
create policy p_guard_permissions_delete on guard_permissions for delete using (
  fn_has_role(school_id, array['admin','director']::app_role[])
);
-- No UPDATE policy: a grant is added or removed, never edited in place.
-- A guard can never satisfy either policy for their OWN profile_id unless
-- they also independently hold admin/director at that school — this is
-- what makes Case 7/Case 8 (self-granting, self-role-change) impossible.

-- ----------------------------------------------------------------------------
-- 4. fn_has_permission — the single real permission check, callable by any
--    authenticated user (needed for both RLS-adjacent wrapper functions
--    below AND the frontend's own get_my_permissions() call).
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
  -- SuperAdmin: global authority, not scoped to any single school.
  if exists (select 1 from user_roles where profile_id = auth.uid() and role::text = 'superadmin') then
    return true;
  end if;

  select role::text into v_role from user_roles
  where profile_id = auth.uid() and school_id = p_school_id
  limit 1;

  if v_role in ('admin','director') then
    return true; -- full authority over their own institution, per the stated hierarchy
  end if;

  if v_role = 'guard' then
    return exists (
      select 1 from guard_permissions gp
      join permissions p on p.id = gp.permission_id
      where gp.profile_id = auth.uid() and gp.school_id = p_school_id and p.permission_key = p_permission_key
    );
  end if;

  return false; -- teacher/driver/parent/no-role: no guard-style permissions apply
end;
$$;
revoke all on function fn_has_permission(text, uuid) from public;
grant execute on function fn_has_permission(text, uuid) to authenticated;

-- ----------------------------------------------------------------------------
-- 5. fn_get_my_permissions — powers the frontend's real (non-shim) check.
--    Returns every permission_key the caller effectively has for a school:
--    ALL of them for admin/director/superadmin (full authority), or the
--    guard's actual granted subset otherwise.
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

  select role::text into v_role from user_roles
  where profile_id = auth.uid() and school_id = p_school_id
  limit 1;

  if v_role in ('admin','director') then
    return query select p.permission_key from permissions p;
  elsif v_role = 'guard' then
    return query
      select p.permission_key from guard_permissions gp
      join permissions p on p.id = gp.permission_id
      where gp.profile_id = auth.uid() and gp.school_id = p_school_id;
  end if;
  return;
end;
$$;
revoke all on function fn_get_my_permissions(uuid) from public;
grant execute on function fn_get_my_permissions(uuid) to authenticated;

-- ----------------------------------------------------------------------------
-- 6. fn_grant_guard_permission / fn_revoke_guard_permission — the RPC
--    surface for Phase 4.2's stated future need (Admin managing a Guard's
--    permissions, Phase 14). Same authorization as the RLS above,
--    duplicated intentionally (defense in depth) and adds an audit_logs
--    entry, which raw table access wouldn't.
-- ----------------------------------------------------------------------------
create or replace function fn_grant_guard_permission(p_profile_id uuid, p_school_id uuid, p_permission_key text)
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_permission_id uuid;
begin
  if not fn_has_role(p_school_id, array['admin','director']::app_role[]) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if not exists (
    select 1 from user_roles where profile_id = p_profile_id and school_id = p_school_id and role = 'guard'
  ) then
    raise exception 'TARGET_IS_NOT_A_GUARD_IN_THIS_SCHOOL';
  end if;

  select id into v_permission_id from permissions where permission_key = p_permission_key;
  if v_permission_id is null then
    raise exception 'UNKNOWN_PERMISSION_KEY: %', p_permission_key;
  end if;

  insert into guard_permissions (profile_id, permission_id, school_id, granted_by)
  values (p_profile_id, v_permission_id, p_school_id, auth.uid())
  on conflict (profile_id, permission_id, school_id) do nothing;

  perform fn_write_audit(p_school_id, 'GRANT_PERMISSION', 'guard_permissions', p_profile_id, null,
    jsonb_build_object('permission_key', p_permission_key));
end;
$$;
revoke all on function fn_grant_guard_permission(uuid, uuid, text) from public;
grant execute on function fn_grant_guard_permission(uuid, uuid, text) to authenticated;

create or replace function fn_revoke_guard_permission(p_profile_id uuid, p_school_id uuid, p_permission_key text)
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_permission_id uuid;
begin
  if not fn_has_role(p_school_id, array['admin','director']::app_role[]) then
    raise exception 'PERMISSION_DENIED';
  end if;

  select id into v_permission_id from permissions where permission_key = p_permission_key;
  delete from guard_permissions
  where profile_id = p_profile_id and school_id = p_school_id and permission_id = v_permission_id;

  perform fn_write_audit(p_school_id, 'REVOKE_PERMISSION', 'guard_permissions', p_profile_id, null,
    jsonb_build_object('permission_key', p_permission_key));
end;
$$;
revoke all on function fn_revoke_guard_permission(uuid, uuid, text) from public;
grant execute on function fn_revoke_guard_permission(uuid, uuid, text) to authenticated;

-- ----------------------------------------------------------------------------
-- 7. fn_guard_* WRAPPER FUNCTIONS — the actual backend enforcement for the
--    4 protected RPCs, WITHOUT modifying them. Each wrapper: derives
--    school_id itself (never trusts a client-supplied value), checks the
--    specific permission for guards (admin/director always pass, per
--    hierarchy), then calls the untouched original function.
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
  select school_id, role::text into v_school_id, v_role from user_roles where profile_id = auth.uid() limit 1;
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if v_role not in ('admin','director') and not fn_has_permission('students.create', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.create';
  end if;

  return fn_register_student(v_school_id, p_full_name, p_student_number, p_class_id, p_academic_year_id, p_birth_date, p_gender);
end;
$$;
revoke all on function fn_guard_register_student(text, text, uuid, uuid, date, text) from public;
grant execute on function fn_guard_register_student(text, text, uuid, uuid, date, text) to authenticated;

create or replace function fn_guard_issue_badge(p_student_id uuid)
returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_school_id uuid;
  v_role text;
begin
  v_school_id := fn_student_school(p_student_id);
  select role::text into v_role from user_roles where profile_id = auth.uid() and school_id = v_school_id limit 1;
  if v_role not in ('admin','director') and not fn_has_permission('students.badge.issue', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.badge.issue';
  end if;
  return fn_issue_badge(p_student_id);
end;
$$;
revoke all on function fn_guard_issue_badge(uuid) from public;
grant execute on function fn_guard_issue_badge(uuid) to authenticated;

create or replace function fn_guard_reissue_badge(p_student_id uuid, p_reason text default null)
returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_school_id uuid;
  v_role text;
begin
  v_school_id := fn_student_school(p_student_id);
  select role::text into v_role from user_roles where profile_id = auth.uid() and school_id = v_school_id limit 1;
  if v_role not in ('admin','director') and not fn_has_permission('students.badge.reissue', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.badge.reissue';
  end if;
  return fn_reissue_badge(p_student_id, p_reason);
end;
$$;
revoke all on function fn_guard_reissue_badge(uuid, text) from public;
grant execute on function fn_guard_reissue_badge(uuid, text) to authenticated;

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
  select role::text into v_role from user_roles where profile_id = auth.uid() and school_id = v_school_id limit 1;
  if v_role not in ('admin','director') and not fn_has_permission('students.badge.suspend', v_school_id) then
    raise exception 'PERMISSION_DENIED: missing students.badge.suspend';
  end if;
  perform fn_suspend_badge(p_badge_id, p_new_status, p_reason);
end;
$$;
revoke all on function fn_guard_suspend_badge(uuid, badge_status, text) from public;
grant execute on function fn_guard_suspend_badge(uuid, badge_status, text) to authenticated;

-- ----------------------------------------------------------------------------
-- 8. ONE-TIME SEED for the existing test account (GUARD001), so the
--    Phase 4.1 dashboard continues working exactly as demonstrated instead
--    of suddenly showing nothing once real permissions replace the old
--    "always true" shim. This is a one-time continuity seed for a KNOWN
--    account, NOT a default policy applied to future guards — granting
--    permissions to new guards is entirely Admin's decision (Phase 14).
-- ----------------------------------------------------------------------------
do $$
declare
  v_profile_id uuid := '4c912460-566d-40bb-9012-b2ebca0a6678'; -- GUARD001
  v_school_id uuid;
begin
  select school_id into v_school_id from user_roles where profile_id = v_profile_id and role = 'guard' limit 1;
  if v_school_id is not null then
    insert into guard_permissions (profile_id, permission_id, school_id, granted_by)
    select v_profile_id, p.id, v_school_id, v_profile_id
    from permissions p
    where p.permission_key in (
      'students.view', 'students.create',
      'students.badge.view', 'students.badge.issue', 'students.badge.reissue', 'students.badge.suspend',
      'classes.view', 'attendance.view'
    )
    on conflict (profile_id, permission_id, school_id) do nothing;
  end if;
end $$;

-- ============================================================================
-- END OF PHASE 4.2 MIGRATION
-- ============================================================================
