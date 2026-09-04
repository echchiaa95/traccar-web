-- ============================================================================
-- PHASE 12 COMPLETE PLATFORM — v5 (schema-faithful to phase2_schema.sql)
-- v5 changes vs v4:
--   * academic_years: legacy column is "label" (+ starts_on/ends_on NOT NULL,
--     derived from the label); every read aliases label -> year_name.
--   * transport fully adopts legacy tables: bus_routes / bus_stops (NO route_id)
--     / bus_route_stops(sequence_order) / student_transport_assignments
--     (academic_year_id+starts_on+is_active NOT NULL) / bus_trips (ENUM
--     trip_direction TO_SCHOOL|TO_HOME, trip_status PLANNED|ACTIVE|COMPLETED|
--     CANCELLED, starts_at/ends_at) / bus_trip_students (snapshot, PK
--     trip_id+student_id) / bus_events (history, bus_event_type BOARD|DROP_OFF,
--     record_source QR|MANUAL). Frontend 'pickup'/'dropoff' are mapped
--     server-side; enum columns never receive lowercase values.
--   * payments: legacy NOT NULL month/year/status + UNIQUE(student_id,month,
--     year) respected; fn_record_payment = check-then-update (increment
--     amount_paid, recompute UPPERCASE status) else insert. Never a 2nd row.
--   * expenses adopt expense_categories(category_id); notes = description.
--   * notifications adopt legacy notifications + notification_deliveries
--     (no parallel notification_reads).
--   * schedule adopts legacy timetables + timetable_entries (weekday 1=Sunday,
--     teacher_id/starts_at/ends_at NOT NULL); no parallel class_schedule.
--   * student_grades: subject_id/score/grade_date NOT NULL respected,
--     teacher_id = teachers.id resolved from auth.uid().
--   * buses.plate_number NOT NULL always filled.
-- ============================================================================
-- supabase/migrations/phase12_complete_platform.sql
-- PHASE 12 (v4 — runs on the REAL legacy schema: payments month/year/status,
--   student_grades teacher_id->teachers(id), buses plate_number NOT NULL,
--   legacy transport tables bus_routes/bus_stops/student_transport_assignments/
--   bus_trips/bus_trip_students adopted as the single transport system) — Complete school-management platform upgrade.
--
-- SAFETY: purely additive.
--   - No DROP TABLE / DROP COLUMN / TRUNCATE / DELETE of existing data.
--   - New columns use ADD COLUMN IF NOT EXISTS.
--   - New policies are created only inside "if not exists (pg_policies)" guards.
--   - Functions use CREATE OR REPLACE with signatures kept compatible with
--     every existing caller (edge functions + older RPC wrappers).
--   - fn_has_permission keeps its (text, uuid) signature; its body now ALSO
--     honors the new user_permissions grants (admin/director still pass,
--     superadmin still passes — no existing caller breaks).
--
-- AUTHORIZATION MODEL:
--   - Identity always comes from auth.uid() -> user_roles, never the client.
--   - All new tables have RLS ENABLED and NO permissive policies; access is
--     exclusively through the SECURITY DEFINER RPCs below, each of which
--     re-verifies role/permission server-side and enforces school isolation.
--   - Passwords/secrets are never written to audit logs.
-- ============================================================================

-- ============================================================================
-- SECTION 0 — SHARED HELPERS
-- ============================================================================

-- 0.1 fn_my_primary_school — the caller's primary school, resolved with the
--     same deterministic role priority as fn_resolve_my_role. Returns NULL
--     for users with no school-bound role (e.g. a pure superadmin).
create or replace function fn_my_primary_school()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select school_id
  from user_roles
  where profile_id = auth.uid()
    and school_id is not null
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

revoke all on function fn_my_primary_school() from public;
grant execute on function fn_my_primary_school() to authenticated;

-- 0.2 fn_is_school_staff — superadmin OR admin/director of the given school.
create or replace function fn_is_school_staff(p_school_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    exists (select 1 from user_roles
            where profile_id = auth.uid() and role::text = 'superadmin')
    or exists (select 1 from user_roles
               where profile_id = auth.uid()
                 and school_id = p_school_id
                 and role::text in ('admin', 'director'));
$$;

revoke all on function fn_is_school_staff(uuid) from public;
grant execute on function fn_is_school_staff(uuid) to authenticated;

-- 0.3 fn_is_school_member — any role bound to the given school, or superadmin.
create or replace function fn_is_school_member(p_school_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    exists (select 1 from user_roles
            where profile_id = auth.uid() and role::text = 'superadmin')
    or exists (select 1 from user_roles
               where profile_id = auth.uid() and school_id = p_school_id);
$$;

revoke all on function fn_is_school_member(uuid) from public;
grant execute on function fn_is_school_member(uuid) to authenticated;

-- 0.4 fn_is_parent_of — true when the caller is a parent linked to the student.
create or replace function fn_is_parent_of(p_student_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from parent_students ps
    join parents pa on pa.id = ps.parent_id
    where ps.student_id = p_student_id
      and pa.profile_id = auth.uid()
  );
$$;

revoke all on function fn_is_parent_of(uuid) from public;
grant execute on function fn_is_parent_of(uuid) to authenticated;

-- 0.5 fn_safe_audit — best-effort audit wrapper: an audit failure must never
--     roll back the business operation. Never pass secrets in p_new.
create or replace function fn_safe_audit(
  p_school_id uuid,
  p_action text,
  p_entity text,
  p_entity_id uuid,
  p_old jsonb,
  p_new jsonb
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform fn_write_audit(p_school_id, p_action, p_entity, p_entity_id, p_old, p_new);
exception when others then
  raise notice 'fn_safe_audit skipped (%).', sqlerrm;
end;
$$;

revoke all on function fn_safe_audit(uuid, text, text, uuid, jsonb, jsonb) from public;
grant execute on function fn_safe_audit(uuid, text, text, uuid, jsonb, jsonb) to authenticated;

-- ============================================================================
-- SECTION 0.B — PERMISSIONS CATALOG BOOTSTRAP (self-contained fix)
-- The catalog table `permissions` was introduced in phase4_2, but Phase 12
-- must be runnable on databases where phase4_2 was never applied or failed.
-- One single catalog source: `permissions`. Additive and idempotent.
-- ============================================================================

create table if not exists permissions (
  id uuid primary key default gen_random_uuid(),
  permission_key text not null unique,
  module text not null,
  name text not null,
  description text,
  created_at timestamptz not null default now()
);

-- In case an older `permissions` table exists without `description`:
alter table permissions add column if not exists description text;

alter table permissions enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'permissions'
      and policyname = 'p_permissions_read'
  ) then
    create policy p_permissions_read on permissions
      for select using (auth.uid() is not null);
  end if;
end $$;

-- Full catalog (phase4_2 base keys + Phase 12 additions). One source of truth.
insert into permissions (permission_key, module, name) values
  ('students.view',          'students',      'عرض التلاميذ'),
  ('students.create',        'students',      'إضافة تلميذ'),
  ('students.update',        'students',      'تعديل تلميذ'),
  ('students.badge.view',    'students',      'عرض البادج'),
  ('students.badge.issue',   'students',      'إصدار بادج'),
  ('students.badge.reissue', 'students',      'إعادة إصدار بادج'),
  ('students.badge.suspend', 'students',      'تعليق بادج'),
  ('attendance.view',        'attendance',    'عرض الحضور'),
  ('attendance.manage',      'attendance',    'إدارة الحضور'),
  ('classes.view',           'classes',       'عرض الأقسام'),
  ('classes.manage',         'classes',       'إدارة الأقسام'),
  ('teachers.view',          'teachers',      'عرض الأساتذة'),
  ('teachers.create',        'teachers',      'إضافة أستاذ'),
  ('teachers.update',        'teachers',      'تعديل أستاذ'),
  ('drivers.view',           'drivers',       'عرض السائقين'),
  ('drivers.create',         'drivers',       'إضافة سائق'),
  ('drivers.update',         'drivers',       'تعديل سائق'),
  ('parents.view',           'parents',       'عرض أولياء الأمور'),
  ('parents.create',         'parents',       'إضافة ولي أمر'),
  ('parents.update',         'parents',       'تعديل ولي أمر'),
  ('transport.view',         'transport',     'عرض النقل'),
  ('transport.manage',       'transport',     'إدارة النقل'),
  ('payments.view',          'payments',      'عرض المدفوعات'),
  ('payments.manage',        'payments',      'إدارة المدفوعات'),
  ('audit.view',             'audit',         'عرض السجل'),
  ('incidents.view',         'incidents',     'عرض المخالفات'),
  ('incidents.create',       'incidents',     'تسجيل مخالفة'),
  ('incidents.manage',       'incidents',     'إدارة المخالفات'),
  ('grades.view',            'grades',        'عرض النقط'),
  ('grades.manage',          'grades',        'إدخال النقط'),
  ('finance.view',           'finance',       'عرض الأداءات والمصاريف'),
  ('finance.manage',         'finance',       'تسجيل الأداءات والمصاريف'),
  ('reports.view',           'reports',       'عرض التقارير'),
  ('notifications.manage',   'notifications', 'إرسال الإشعارات'),
  ('schedule.view',          'schedule',      'عرض الجداول'),
  ('schedule.manage',        'schedule',      'إدارة الجداول'),
  ('subjects.manage',        'subjects',      'إدارة المواد')
on conflict (permission_key) do nothing;

-- ============================================================================
-- SECTION 1 — USER PERMISSIONS (real, per-user grants)
-- ============================================================================

create table if not exists user_permissions (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  school_id uuid not null references schools(id) on delete cascade,
  permission_key text not null references permissions(permission_key) on delete cascade,
  granted_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  unique (profile_id, school_id, permission_key)
);

alter table user_permissions enable row level security;

-- Users may read their OWN grants (the guard console gates its UI with this);
-- everything else goes through the SECURITY DEFINER RPCs below.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'user_permissions'
      and policyname = 'p_user_permissions_self_read'
  ) then
    create policy p_user_permissions_self_read on user_permissions
      for select using (profile_id = auth.uid());
  end if;
end $$;

-- Permission catalog additions (additive; existing keys untouched).
insert into permissions (permission_key, module, name) values
  ('incidents.view',        'incidents',     'عرض المخالفات'),
  ('incidents.create',      'incidents',     'تسجيل مخالفة'),
  ('incidents.manage',      'incidents',     'إدارة المخالفات'),
  ('grades.view',           'grades',        'عرض النقط'),
  ('grades.manage',         'grades',        'إدخال النقط'),
  ('finance.view',          'finance',       'عرض الأداءات والمصاريف'),
  ('finance.manage',        'finance',       'تسجيل الأداءات والمصاريف'),
  ('reports.view',          'reports',       'عرض التقارير'),
  ('notifications.manage',  'notifications', 'إرسال الإشعارات'),
  ('schedule.view',         'schedule',      'عرض الجداول'),
  ('schedule.manage',       'schedule',      'إدارة الجداول'),
  ('subjects.manage',       'subjects',      'إدارة المواد'),
  ('students.update',       'students',      'تعديل تلميذ')
on conflict (permission_key) do nothing;

-- 1.1 fn_has_permission — REPLACED body, SAME signature (text, uuid).
--     Resolution order: superadmin -> admin/director of the school ->
--     explicit user_permissions grant. Existing callers (edge functions,
--     fn_guard_* wrappers) keep working unchanged.
create or replace function fn_has_permission(p_permission_key text, p_school_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_role text;
begin
  if auth.uid() is null then
    return false;
  end if;

  if exists (select 1 from user_roles
             where profile_id = auth.uid() and role::text = 'superadmin') then
    return true;
  end if;

  v_role := fn_resolve_my_role(p_school_id);
  if v_role in ('admin', 'director') then
    return true;
  end if;

  return exists (
    select 1 from user_permissions
    where profile_id = auth.uid()
      and school_id = p_school_id
      and permission_key = p_permission_key
  );
end;
$$;

revoke all on function fn_has_permission(text, uuid) from public;
grant execute on function fn_has_permission(text, uuid) to authenticated;

-- 1.2 fn_my_permissions — every key the caller effectively holds, platform-wide.
--     Used by the frontend to gate UI. Server-side checks still re-run on
--     every mutation; this is a read-only mirror for rendering.
create or replace function fn_my_permissions()
returns setof text
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    return;
  end if;

  -- superadmin / admin / director: full catalog.
  if exists (select 1 from user_roles
             where profile_id = auth.uid()
               and role::text in ('superadmin', 'admin', 'director')) then
    return query select permission_key from permissions;
    return;
  end if;

  -- other roles: explicit grants only.
  return query
    select up.permission_key
    from user_permissions up
    where up.profile_id = auth.uid();
end;
$$;

revoke all on function fn_my_permissions() from public;
grant execute on function fn_my_permissions() to authenticated;

-- 1.3 fn_get_user_permissions — grants of one user inside one school.
--     Caller: superadmin, or admin/director of that school.
create or replace function fn_get_user_permissions(p_profile_id uuid, p_school_id uuid)
returns setof text
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if not fn_is_school_staff(p_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
    select up.permission_key
    from user_permissions up
    where up.profile_id = p_profile_id
      and up.school_id = p_school_id
    order by up.permission_key;
end;
$$;

revoke all on function fn_get_user_permissions(uuid, uuid) from public;
grant execute on function fn_get_user_permissions(uuid, uuid) to authenticated;

-- 1.4 fn_grant_user_permission — grant one key to one user in one school.
create or replace function fn_grant_user_permission(
  p_profile_id uuid,
  p_school_id uuid,
  p_permission_key text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not fn_is_school_staff(p_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- The target must actually belong to this school.
  if not exists (select 1 from user_roles
                 where profile_id = p_profile_id and school_id = p_school_id) then
    raise exception 'USER_NOT_IN_SCHOOL';
  end if;

  -- The key must exist in the catalog.
  if not exists (select 1 from permissions where permission_key = p_permission_key) then
    raise exception 'UNKNOWN_PERMISSION';
  end if;

  insert into user_permissions (profile_id, school_id, permission_key, granted_by)
  values (p_profile_id, p_school_id, p_permission_key, auth.uid())
  on conflict (profile_id, school_id, permission_key) do nothing;

  perform fn_safe_audit(p_school_id, 'GRANT_PERMISSION', 'user_permissions', p_profile_id,
    null, jsonb_build_object('permission_key', p_permission_key));
end;
$$;

revoke all on function fn_grant_user_permission(uuid, uuid, text) from public;
grant execute on function fn_grant_user_permission(uuid, uuid, text) to authenticated;

-- 1.5 fn_revoke_user_permission — revoke one key.
create or replace function fn_revoke_user_permission(
  p_profile_id uuid,
  p_school_id uuid,
  p_permission_key text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not fn_is_school_staff(p_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  delete from user_permissions
  where profile_id = p_profile_id
    and school_id = p_school_id
    and permission_key = p_permission_key;

  perform fn_safe_audit(p_school_id, 'REVOKE_PERMISSION', 'user_permissions', p_profile_id,
    jsonb_build_object('permission_key', p_permission_key), null);
end;
$$;

revoke all on function fn_revoke_user_permission(uuid, uuid, text) from public;
grant execute on function fn_revoke_user_permission(uuid, uuid, text) to authenticated;

-- ============================================================================
-- SECTION 2 — SCHOOLS: full institution profile
-- ============================================================================

alter table schools add column if not exists legal_name text;
alter table schools add column if not exists logo_url text;
alter table schools add column if not exists address text;
alter table schools add column if not exists city text;
alter table schools add column if not exists region text;
alter table schools add column if not exists phone text;
alter table schools add column if not exists email text;
alter table schools add column if not exists website text;
alter table schools add column if not exists director_name text;
alter table schools add column if not exists school_type text;
alter table schools add column if not exists ice text;
alter table schools add column if not exists notes text;
alter table schools add column if not exists is_disabled boolean not null default false;
alter table schools add column if not exists created_at timestamptz not null default now();

-- profiles.created_at for the user directory (additive; existing rows get now()).
alter table profiles add column if not exists created_at timestamptz not null default now();

-- 2.1 fn_create_school_full — school creation with the complete profile.
--     SuperAdmin only. p_data jsonb keeps the signature stable for future
--     fields without breaking callers.
create or replace function fn_create_school_full(p_name text, p_data jsonb default '{}'::jsonb)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  if not fn_is_superadmin() then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_name is null or trim(p_name) = '' then
    raise exception 'SCHOOL_NAME_REQUIRED';
  end if;

  insert into schools (name, legal_name, address, city, region, phone, email,
                       website, director_name, school_type, ice, notes)
  values (
    trim(p_name),
    nullif(trim(coalesce(p_data->>'legal_name', '')), ''),
    nullif(trim(coalesce(p_data->>'address', '')), ''),
    nullif(trim(coalesce(p_data->>'city', '')), ''),
    nullif(trim(coalesce(p_data->>'region', '')), ''),
    nullif(trim(coalesce(p_data->>'phone', '')), ''),
    nullif(trim(coalesce(p_data->>'email', '')), ''),
    nullif(trim(coalesce(p_data->>'website', '')), ''),
    nullif(trim(coalesce(p_data->>'director_name', '')), ''),
    nullif(trim(coalesce(p_data->>'school_type', '')), ''),
    nullif(trim(coalesce(p_data->>'ice', '')), ''),
    nullif(trim(coalesce(p_data->>'notes', '')), '')
  )
  returning id into v_school_id;

  perform fn_safe_audit(v_school_id, 'CREATE_SCHOOL', 'schools', v_school_id,
    null, jsonb_build_object('name', trim(p_name)));

  return v_school_id;
end;
$$;

revoke all on function fn_create_school_full(text, jsonb) from public;
grant execute on function fn_create_school_full(text, jsonb) to authenticated;

-- 2.2 fn_update_school — edit the institution profile.
--     SuperAdmin (any school) or admin/director of that school.
create or replace function fn_update_school(p_school_id uuid, p_data jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not fn_is_school_staff(p_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if not exists (select 1 from schools where id = p_school_id) then
    raise exception 'INVALID_SCHOOL';
  end if;

  update schools set
    name          = coalesce(nullif(trim(coalesce(p_data->>'name', '')), ''), name),
    legal_name    = case when p_data ? 'legal_name'    then nullif(trim(p_data->>'legal_name'), '')    else legal_name end,
    logo_url      = case when p_data ? 'logo_url'      then nullif(trim(p_data->>'logo_url'), '')      else logo_url end,
    address       = case when p_data ? 'address'       then nullif(trim(p_data->>'address'), '')       else address end,
    city          = case when p_data ? 'city'          then nullif(trim(p_data->>'city'), '')          else city end,
    region        = case when p_data ? 'region'        then nullif(trim(p_data->>'region'), '')        else region end,
    phone         = case when p_data ? 'phone'         then nullif(trim(p_data->>'phone'), '')         else phone end,
    email         = case when p_data ? 'email'         then nullif(trim(p_data->>'email'), '')         else email end,
    website       = case when p_data ? 'website'       then nullif(trim(p_data->>'website'), '')       else website end,
    director_name = case when p_data ? 'director_name' then nullif(trim(p_data->>'director_name'), '') else director_name end,
    school_type   = case when p_data ? 'school_type'   then nullif(trim(p_data->>'school_type'), '')   else school_type end,
    ice           = case when p_data ? 'ice'           then nullif(trim(p_data->>'ice'), '')           else ice end,
    notes         = case when p_data ? 'notes'         then nullif(trim(p_data->>'notes'), '')         else notes end
  where id = p_school_id;

  perform fn_safe_audit(p_school_id, 'UPDATE_SCHOOL', 'schools', p_school_id, null, p_data);
end;
$$;

revoke all on function fn_update_school(uuid, jsonb) from public;
grant execute on function fn_update_school(uuid, jsonb) to authenticated;

-- 2.3 fn_get_school_profile — full profile for members of the school
--     (and superadmin). Used by the director console and page headers.
create or replace function fn_get_school_profile(p_school_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_result jsonb;
begin
  if not fn_is_school_member(p_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  select to_jsonb(s) into v_result
  from schools s
  where s.id = p_school_id;

  if v_result is null then
    raise exception 'INVALID_SCHOOL';
  end if;
  return v_result;
end;
$$;

revoke all on function fn_get_school_profile(uuid) from public;
grant execute on function fn_get_school_profile(uuid) to authenticated;

-- 2.4 fn_list_schools_full — SuperAdmin directory with per-school counts.
create or replace function fn_list_schools_full()
returns table(
  school_id uuid,
  school_name text,
  legal_name text,
  city text,
  phone text,
  email text,
  logo_url text,
  director_name text,
  school_type text,
  is_disabled boolean,
  created_at timestamptz,
  student_count bigint,
  staff_count bigint,
  account_count bigint
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not fn_is_superadmin() then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select
    s.id, s.name, s.legal_name, s.city, s.phone, s.email, s.logo_url,
    s.director_name, s.school_type, s.is_disabled, s.created_at,
    (select count(*) from students st where st.school_id = s.id and st.deleted_at is null),
    (select count(*) from (
       select t.id from teachers t where t.school_id = s.id and t.deleted_at is null
       union all select d.id from drivers d where d.school_id = s.id and d.deleted_at is null
       union all select g.id from guards g where g.school_id = s.id
       union all select pa.id from parents pa where pa.school_id = s.id and pa.deleted_at is null
     ) staff),
    (select count(*) from user_roles ur where ur.school_id = s.id)
  from schools s
  order by s.created_at desc;
end;
$$;

revoke all on function fn_list_schools_full() from public;
grant execute on function fn_list_schools_full() to authenticated;

-- 2.5 fn_list_all_users_v2 — global user directory with role/school/status
--     filters, search, and pagination. SuperAdmin only.
create or replace function fn_list_all_users_v2(
  p_query text default null,
  p_role text default null,
  p_school_id uuid default null,
  p_status text default null,       -- 'active' | 'disabled' | null
  p_limit int default 25,
  p_offset int default 0
)
returns table(
  profile_id uuid,
  full_name text,
  user_number text,
  phone text,
  is_disabled boolean,
  created_at timestamptz,
  roles jsonb,
  school_names jsonb
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not fn_is_superadmin() then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select
    p.id, p.full_name, p.user_number, p.phone, p.is_disabled, p.created_at,
    coalesce((select jsonb_agg(distinct ur.role::text)
              from user_roles ur where ur.profile_id = p.id), '[]'::jsonb),
    coalesce((select jsonb_agg(distinct s.name)
              from user_roles ur join schools s on s.id = ur.school_id
              where ur.profile_id = p.id), '[]'::jsonb)
  from profiles p
  where (p_query is null or p_query = ''
         or p.full_name ilike '%' || p_query || '%'
         or p.user_number ilike '%' || p_query || '%'
         or coalesce(p.phone, '') ilike '%' || p_query || '%')
    and (p_status is null or p_status = ''
         or (p_status = 'disabled' and p.is_disabled)
         or (p_status = 'active' and not p.is_disabled))
    and (p_role is null or p_role = ''
         or exists (select 1 from user_roles ur
                    where ur.profile_id = p.id and ur.role::text = p_role))
    and (p_school_id is null
         or exists (select 1 from user_roles ur
                    where ur.profile_id = p.id and ur.school_id = p_school_id))
  order by p.created_at desc
  limit p_limit offset p_offset;
end;
$$;

revoke all on function fn_list_all_users_v2(text, text, uuid, text, int, int) from public;
grant execute on function fn_list_all_users_v2(text, text, uuid, text, int, int) to authenticated;

-- 2.6 fn_update_profile — edit name/phone of a user.
--     SuperAdmin (any user) or admin/director sharing a school with the target.
create or replace function fn_update_profile(
  p_profile_id uuid,
  p_full_name text default null,
  p_phone text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_allowed boolean;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;

  select fn_is_superadmin()
     or exists (
       select 1
       from user_roles mine
       join user_roles theirs on theirs.school_id = mine.school_id
       where mine.profile_id = auth.uid()
         and mine.role::text in ('admin', 'director')
         and theirs.profile_id = p_profile_id
     )
  into v_allowed;

  -- A user may always fix their own name/phone.
  if not v_allowed and auth.uid() = p_profile_id then
    v_allowed := true;
  end if;

  if not v_allowed then
    raise exception 'PERMISSION_DENIED';
  end if;

  update profiles set
    full_name = coalesce(nullif(trim(coalesce(p_full_name, '')), ''), full_name),
    phone     = case when p_phone is not null then nullif(trim(p_phone), '') else phone end
  where id = p_profile_id;

  perform fn_safe_audit(fn_my_primary_school(), 'UPDATE_PROFILE', 'profiles', p_profile_id,
    null, jsonb_build_object('full_name', p_full_name, 'phone', p_phone));
end;
$$;

revoke all on function fn_update_profile(uuid, text, text) from public;
grant execute on function fn_update_profile(uuid, text, text) to authenticated;

-- ============================================================================
-- SECTION 3 — ACADEMIC STRUCTURE (my-school variants + management)
-- ============================================================================

alter table classes add column if not exists teacher_id uuid;
alter table classes add column if not exists capacity integer;
alter table classes add column if not exists is_disabled boolean not null default false;
alter table academic_years add column if not exists is_disabled boolean not null default false;

-- 3.1 fn_create_academic_year_my — year creation for the CALLER's school.
--     The school is derived from auth.uid() -> user_roles; the frontend never
--     sends a school_id. Duplicate year names per school are rejected.
create or replace function fn_create_academic_year_my(
  p_name text,
  p_is_current boolean default false
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_year_id uuid;
  v_start_year int;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;

  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;

  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_name is null or trim(p_name) = '' then
    raise exception 'YEAR_NAME_REQUIRED';
  end if;

  -- Legacy column is "label" (text NOT NULL), not "name".
  if exists (select 1 from academic_years
             where school_id = v_school_id and label = trim(p_name)) then
    raise exception 'ACADEMIC_YEAR_EXISTS';
  end if;

  -- starts_on / ends_on are NOT NULL in the legacy schema: derive them from
  -- the label (e.g. '2026/2027' -> 2026-09-01 .. 2027-06-30).
  v_start_year := nullif(substring(trim(p_name) from '(\d{4})'), '')::int;
  if v_start_year is null then
    v_start_year := extract(year from current_date)::int;
  end if;

  if p_is_current then
    update academic_years set is_current = false
    where school_id = v_school_id and is_current = true;
  end if;

  -- The first year of a school becomes current automatically.
  insert into academic_years (school_id, label, starts_on, ends_on, is_current)
  values (
    v_school_id,
    trim(p_name),
    make_date(v_start_year, 9, 1),
    make_date(v_start_year + 1, 6, 30),
    coalesce(p_is_current, false)
       or not exists (select 1 from academic_years where school_id = v_school_id)
  )
  returning id into v_year_id;

  perform fn_safe_audit(v_school_id, 'CREATE_ACADEMIC_YEAR', 'academic_years', v_year_id,
    null, jsonb_build_object('name', trim(p_name), 'is_current', p_is_current));

  return v_year_id;
end;
$$;

revoke all on function fn_create_academic_year_my(text, boolean) from public;
grant execute on function fn_create_academic_year_my(text, boolean) to authenticated;

-- 3.2 fn_set_current_academic_year — mark one year current (unmarks others).
create or replace function fn_set_current_academic_year(p_year_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select school_id into v_school_id from academic_years where id = p_year_id;
  if v_school_id is null then
    raise exception 'INVALID_ACADEMIC_YEAR';
  end if;
  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  update academic_years set is_current = false
  where school_id = v_school_id and is_current = true;
  update academic_years set is_current = true, is_disabled = false
  where id = p_year_id;

  perform fn_safe_audit(v_school_id, 'SET_CURRENT_YEAR', 'academic_years', p_year_id, null, null);
end;
$$;

revoke all on function fn_set_current_academic_year(uuid) from public;
grant execute on function fn_set_current_academic_year(uuid) to authenticated;

-- 3.3 fn_update_academic_year — rename / enable-disable a year.
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
begin
  select school_id into v_school_id from academic_years where id = p_year_id;
  if v_school_id is null then
    raise exception 'INVALID_ACADEMIC_YEAR';
  end if;
  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_name is not null and trim(p_name) <> '' then
    -- Legacy column is "label".
    if exists (select 1 from academic_years
               where school_id = v_school_id and label = trim(p_name) and id <> p_year_id) then
      raise exception 'ACADEMIC_YEAR_EXISTS';
    end if;
    update academic_years set label = trim(p_name) where id = p_year_id;
  end if;

  if p_is_disabled is not null then
    -- A disabled year cannot stay the current one.
    update academic_years
    set is_disabled = p_is_disabled,
        is_current = case when p_is_disabled then false else is_current end
    where id = p_year_id;
  end if;

  perform fn_safe_audit(v_school_id, 'UPDATE_ACADEMIC_YEAR', 'academic_years', p_year_id,
    null, jsonb_build_object('name', p_name, 'is_disabled', p_is_disabled));
end;
$$;

revoke all on function fn_update_academic_year(uuid, text, boolean) from public;
grant execute on function fn_update_academic_year(uuid, text, boolean) to authenticated;

-- 3.4 fn_create_class_my — class creation under a year of the CALLER's school.
--     Optionally assigns a responsible teacher (must belong to same school).
create or replace function fn_create_class_my(
  p_academic_year_id uuid,
  p_name text,
  p_level text default null,
  p_capacity integer default null,
  p_teacher_id uuid default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_class_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;

  select school_id into v_school_id from academic_years where id = p_academic_year_id;
  if v_school_id is null then
    raise exception 'INVALID_ACADEMIC_YEAR';
  end if;

  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_name is null or trim(p_name) = '' then
    raise exception 'CLASS_NAME_REQUIRED';
  end if;

  if p_teacher_id is not null and not exists (
    select 1 from teachers
    where id = p_teacher_id and school_id = v_school_id and deleted_at is null
  ) then
    raise exception 'INVALID_TEACHER';
  end if;

  insert into classes (school_id, academic_year_id, name, level, capacity, teacher_id)
  values (v_school_id, p_academic_year_id, trim(p_name),
          nullif(trim(coalesce(p_level, '')), ''), p_capacity, p_teacher_id)
  returning id into v_class_id;

  perform fn_safe_audit(v_school_id, 'CREATE_CLASS', 'classes', v_class_id,
    null, jsonb_build_object('name', trim(p_name), 'level', p_level));

  return v_class_id;
end;
$$;

revoke all on function fn_create_class_my(uuid, text, text, integer, uuid) from public;
grant execute on function fn_create_class_my(uuid, text, text, integer, uuid) to authenticated;

-- 3.5 fn_update_class — rename / level / capacity / teacher / enable-disable.
create or replace function fn_update_class(
  p_class_id uuid,
  p_name text default null,
  p_level text default null,
  p_capacity integer default null,
  p_teacher_id uuid default null,
  p_is_disabled boolean default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;
  if not fn_is_school_staff(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_teacher_id is not null and not exists (
    select 1 from teachers
    where id = p_teacher_id and school_id = v_school_id and deleted_at is null
  ) then
    raise exception 'INVALID_TEACHER';
  end if;

  update classes set
    name        = coalesce(nullif(trim(coalesce(p_name, '')), ''), name),
    level       = case when p_level is not null then nullif(trim(p_level), '') else level end,
    capacity    = coalesce(p_capacity, capacity),
    teacher_id  = coalesce(p_teacher_id, teacher_id),
    is_disabled = coalesce(p_is_disabled, is_disabled)
  where id = p_class_id;

  perform fn_safe_audit(v_school_id, 'UPDATE_CLASS', 'classes', p_class_id,
    null, jsonb_build_object('name', p_name, 'level', p_level));
end;
$$;

revoke all on function fn_update_class(uuid, text, text, integer, uuid, boolean) from public;
grant execute on function fn_update_class(uuid, text, text, integer, uuid, boolean) to authenticated;

-- 3.6 fn_list_my_classes — classes of the caller's school (optionally one
--     year) with live student counts and the responsible teacher's name.
create or replace function fn_list_my_classes(p_academic_year_id uuid default null)
returns table(
  class_id uuid,
  class_name text,
  level text,
  capacity integer,
  is_disabled boolean,
  academic_year_id uuid,
  year_name text,
  teacher_id uuid,
  teacher_name text,
  student_count bigint
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select
    c.id, c.name, c.level, c.capacity, c.is_disabled, c.academic_year_id,
    ay.label, c.teacher_id,
    (select p.full_name from teachers t join profiles p on p.id = t.profile_id
     where t.id = c.teacher_id),
    (select count(*) from student_enrollments se
     where se.class_id = c.id and se.status = 'ACTIVE')
  from classes c
  join academic_years ay on ay.id = c.academic_year_id
  where c.school_id = v_school_id
    and (p_academic_year_id is null or c.academic_year_id = p_academic_year_id)
  order by ay.is_current desc, ay.label desc, c.name;
end;
$$;

revoke all on function fn_list_my_classes(uuid) from public;
grant execute on function fn_list_my_classes(uuid) to authenticated;

-- 3.7 fn_list_my_academic_years — caller's school years, current first.
create or replace function fn_list_my_academic_years()
returns table(year_id uuid, year_name text, is_current boolean, is_disabled boolean, class_count bigint)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select ay.id, ay.label, ay.is_current, ay.is_disabled,
    (select count(*) from classes c where c.academic_year_id = ay.id)
  from academic_years ay
  where ay.school_id = v_school_id
  order by ay.is_current desc, ay.label desc;
end;
$$;

revoke all on function fn_list_my_academic_years() from public;
grant execute on function fn_list_my_academic_years() to authenticated;

-- ============================================================================
-- SECTION 4 — SUBJECTS
-- ============================================================================

-- subjects exists in phase2_schema WITHOUT unique(school_id, name) and possibly
-- with a different column set. CREATE IF NOT EXISTS covers fresh databases;
-- the ALTERs below adapt the pre-existing table without touching its data.
create table if not exists subjects (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);

alter table subjects add column if not exists school_id uuid references schools(id);
alter table subjects add column if not exists name text;
alter table subjects add column if not exists created_at timestamptz not null default now();
create index if not exists ix_subjects_school_name on subjects (school_id, name);

alter table subjects enable row level security;

create or replace function fn_create_subject(p_name text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('subjects.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_name is null or trim(p_name) = '' then
    raise exception 'SUBJECT_NAME_REQUIRED';
  end if;

  -- No unique constraint is assumed on (school_id, name) because the legacy
  -- phase2 table lacks one: check-then-insert instead of ON CONFLICT.
  select id into v_id from subjects
  where school_id = v_school_id and name = trim(p_name)
  limit 1;
  if v_id is null then
    insert into subjects (school_id, name) values (v_school_id, trim(p_name))
    returning id into v_id;
  end if;

  return v_id;
end;
$$;

revoke all on function fn_create_subject(text) from public;
grant execute on function fn_create_subject(text) to authenticated;

create or replace function fn_list_subjects()
returns table(subject_id uuid, subject_name text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select s.id, s.name from subjects s
  where s.school_id = v_school_id
  order by s.name;
end;
$$;

revoke all on function fn_list_subjects() from public;
grant execute on function fn_list_subjects() to authenticated;

-- ============================================================================
-- SECTION 5 — ATTENDANCE
-- ============================================================================

create table if not exists attendance_records (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  class_id uuid not null references classes(id) on delete cascade,
  att_date date not null,
  status text not null check (status in ('present', 'absent', 'late', 'excused')),
  note text,
  recorded_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (student_id, class_id, att_date)
);

create index if not exists ix_attendance_school_date on attendance_records (school_id, att_date);
create index if not exists ix_attendance_student on attendance_records (student_id, att_date);

alter table attendance_records enable row level security;

-- Unique upsert key required by fn_save_attendance's ON CONFLICT.
create unique index if not exists ux_attendance_records_scd
  on attendance_records (student_id, class_id, att_date);

-- 5.1 fn_save_attendance — bulk upsert of one class roster for one date.
--     p_rows: jsonb array of {"student_id": uuid, "status": "present|absent|late|excused", "note": text?}
--     Allowed: school staff, the teacher responsible for the class, any
--     teacher of the school, or attendance.manage grant.
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
  v_is_teacher boolean;
begin
  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;

  select exists (
    select 1 from teachers t
    where t.school_id = v_school_id
      and t.profile_id = auth.uid()
      and t.deleted_at is null
  ) into v_is_teacher;

  if not (fn_is_school_staff(v_school_id)
          or v_is_teacher
          or fn_has_permission('attendance.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
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

revoke all on function fn_save_attendance(uuid, date, jsonb) from public;
grant execute on function fn_save_attendance(uuid, date, jsonb) to authenticated;

-- 5.2 fn_get_class_attendance — roster + saved status for one class/date.
create or replace function fn_get_class_attendance(p_class_id uuid, p_date date default null)
returns table(student_id uuid, full_name text, student_number text, status text, note text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;
  if not (fn_is_school_member(v_school_id)
          or fn_has_permission('attendance.view', v_school_id)) then
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

revoke all on function fn_get_class_attendance(uuid, date) from public;
grant execute on function fn_get_class_attendance(uuid, date) to authenticated;

-- 5.3 fn_student_attendance — one student's records in a date range.
--     Staff of the school, attendance.view grant, or the parent of the student.
create or replace function fn_student_attendance(
  p_student_id uuid,
  p_from date default null,
  p_to date default null
)
returns table(att_date date, status text, class_name text, note text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('attendance.view', v_school_id)
          or fn_is_parent_of(p_student_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select ar.att_date, ar.status, c.name, ar.note
  from attendance_records ar
  join classes c on c.id = ar.class_id
  where ar.student_id = p_student_id
    and ar.att_date between coalesce(p_from, current_date - 90) and coalesce(p_to, current_date)
  order by ar.att_date desc;
end;
$$;

revoke all on function fn_student_attendance(uuid, date, date) from public;
grant execute on function fn_student_attendance(uuid, date, date) to authenticated;

-- 5.4 fn_school_attendance_today — per-status counts for the dashboard.
create or replace function fn_school_attendance_today()
returns table(present bigint, absent bigint, late bigint, excused bigint, total_marked bigint)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select
    count(*) filter (where ar.status = 'present'),
    count(*) filter (where ar.status = 'absent'),
    count(*) filter (where ar.status = 'late'),
    count(*) filter (where ar.status = 'excused'),
    count(*)
  from attendance_records ar
  where ar.school_id = v_school_id
    and ar.att_date = current_date;
end;
$$;

revoke all on function fn_school_attendance_today() from public;
grant execute on function fn_school_attendance_today() to authenticated;

-- 5.5 fn_report_attendance — flat rows for reports/CSV (staff + reports.view).
create or replace function fn_report_attendance(
  p_from date,
  p_to date,
  p_class_id uuid default null
)
returns table(att_date date, student_name text, student_number text, class_name text, status text, note text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('reports.view', v_school_id)
          or fn_has_permission('attendance.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select ar.att_date, st.full_name, st.student_number, c.name, ar.status, ar.note
  from attendance_records ar
  join students st on st.id = ar.student_id
  join classes c on c.id = ar.class_id
  where ar.school_id = v_school_id
    and ar.att_date between coalesce(p_from, current_date - 30) and coalesce(p_to, current_date)
    and (p_class_id is null or ar.class_id = p_class_id)
  order by ar.att_date desc, st.full_name
  limit 2000;
end;
$$;

revoke all on function fn_report_attendance(date, date, uuid) from public;
grant execute on function fn_report_attendance(date, date, uuid) to authenticated;

-- ============================================================================
-- SECTION 6 — GRADES
-- ============================================================================

-- student_grades exists in phase2_schema with a DIFFERENT structure.
-- CREATE IF NOT EXISTS covers fresh databases; the ALTERs add every column
-- Phase 12 needs to the legacy table without touching existing rows.
-- Fresh installs get the EXACT legacy shape (student_id/subject_id/score/
-- grade_date NOT NULL, teacher_id -> teachers(id)). Existing legacy tables are
-- extended only via additive ALTERs below.
create table if not exists student_grades (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  subject_id uuid not null references subjects(id) on delete cascade,
  teacher_id uuid references teachers(id),
  grade_type text,
  period text,
  grade_date date not null default current_date,
  score numeric(5,2) not null check (score >= 0),
  note text,
  created_at timestamptz not null default now()
);

-- Additive Phase-12 columns (all nullable / defaulted — legacy rows untouched).
-- subject_id, score, grade_date, note, period, grade_type, teacher_id already
-- exist in the legacy table with the right types/FKs: never re-add them.
alter table student_grades add column if not exists school_id uuid references schools(id);
alter table student_grades add column if not exists class_id uuid references classes(id) on delete set null;
alter table student_grades add column if not exists max_score numeric not null default 20;
alter table student_grades add column if not exists created_at timestamptz not null default now();

create index if not exists ix_grades_student on student_grades (student_id, created_at desc);
create index if not exists ix_grades_class on student_grades (class_id, subject_id);

alter table student_grades enable row level security;

-- 6.1 fn_add_grade — staff, any teacher of the school, or grades.manage.
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
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;

  -- The caller's teachers row (teachers.id) — student_grades.teacher_id has a
  -- legacy FK to teachers(id), so auth.uid() is never stored directly.
  select t.id into v_teacher_id
  from teachers t
  where t.school_id = v_school_id and t.profile_id = auth.uid()
    and t.deleted_at is null
  limit 1;

  if not (fn_is_school_staff(v_school_id) or v_teacher_id is not null
          or fn_has_permission('grades.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- Legacy NOT NULL columns must never receive NULL:
  if p_subject_id is null then
    raise exception 'GRADE_SUBJECT_REQUIRED';
  end if;
  if not exists (select 1 from subjects s where s.id = p_subject_id and s.school_id = v_school_id) then
    raise exception 'INVALID_SUBJECT';
  end if;
  if p_score is null or p_score < 0 then
    raise exception 'INVALID_SCORE';
  end if;

  insert into student_grades
    (school_id, student_id, class_id, subject_id, period, grade_type, score, max_score, note, grade_date, teacher_id)
  values (
    v_school_id, p_student_id, p_class_id, p_subject_id,
    nullif(trim(coalesce(p_period, '')), ''),
    coalesce(nullif(trim(coalesce(p_grade_type, '')), ''), 'تقويم'),
    p_score, coalesce(p_max_score, 20),
    nullif(trim(coalesce(p_note, '')), ''),
    current_date,           -- grade_date NOT NULL (legacy default kept explicit)
    v_teacher_id            -- teachers.id resolved from profile_id = auth.uid()
  )
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'ADD_GRADE', 'student_grades', v_id,
    null, jsonb_build_object('student_id', p_student_id, 'score', p_score));

  return v_id;
end;
$$;

revoke all on function fn_add_grade(uuid, uuid, uuid, text, text, numeric, numeric, text) from public;
grant execute on function fn_add_grade(uuid, uuid, uuid, text, text, numeric, numeric, text) to authenticated;

-- 6.2 fn_list_student_grades — staff, grades.view, or parent of the student.
create or replace function fn_list_student_grades(p_student_id uuid)
returns table(
  grade_id uuid, subject_name text, period text, grade_type text,
  score numeric, max_score numeric, note text, teacher_name text, created_at timestamptz
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('grades.view', v_school_id)
          or fn_is_parent_of(p_student_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select g.id, su.name, g.period, g.grade_type, g.score, g.max_score, g.note,
         (select p.full_name from teachers t join profiles p on p.id = t.profile_id
          where t.id = g.teacher_id),
         g.created_at
  from student_grades g
  left join subjects su on su.id = g.subject_id
  where g.student_id = p_student_id
  order by g.created_at desc
  limit 200;
end;
$$;

revoke all on function fn_list_student_grades(uuid) from public;
grant execute on function fn_list_student_grades(uuid) to authenticated;

-- ============================================================================
-- SECTION 7 — BEHAVIOR & INCIDENTS (السلوك والمخالفات — includes smoking)
-- ============================================================================

create table if not exists incidents (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  type text not null,               -- تدخين / عنف / شجار / تأخر / غياب متكرر / مخالفة نقل / ملاحظة تربوية ...
  title text not null,
  description text,
  place text,
  occurred_at timestamptz not null default now(),
  action_taken text,
  status text not null default 'open' check (status in ('open', 'closed')),
  reported_by uuid references profiles(id),
  created_at timestamptz not null default now()
);

create index if not exists ix_incidents_school on incidents (school_id, status, created_at desc);

alter table incidents enable row level security;

-- 7.1 fn_report_incident — staff, incidents.create grant (e.g. a guard), or
--     any teacher of the school (educational notes).
create or replace function fn_report_incident(
  p_student_id uuid,
  p_type text,
  p_title text,
  p_description text default null,
  p_place text default null,
  p_occurred_at timestamptz default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_id uuid;
  v_is_teacher boolean;
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;

  select exists (select 1 from teachers t
                 where t.school_id = v_school_id and t.profile_id = auth.uid()
                   and t.deleted_at is null)
  into v_is_teacher;

  if not (fn_is_school_staff(v_school_id) or v_is_teacher
          or fn_has_permission('incidents.create', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_title is null or trim(p_title) = '' then
    raise exception 'INCIDENT_TITLE_REQUIRED';
  end if;

  insert into incidents (school_id, student_id, type, title, description, place, occurred_at, reported_by)
  values (
    v_school_id, p_student_id,
    nullif(trim(coalesce(p_type, '')), 'مخالفة'),
    trim(p_title),
    nullif(trim(coalesce(p_description, '')), ''),
    nullif(trim(coalesce(p_place, '')), ''),
    coalesce(p_occurred_at, now()),
    auth.uid()
  )
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'REPORT_INCIDENT', 'incidents', v_id,
    null, jsonb_build_object('student_id', p_student_id, 'type', p_type));

  return v_id;
end;
$$;

revoke all on function fn_report_incident(uuid, text, text, text, text, timestamptz) from public;
grant execute on function fn_report_incident(uuid, text, text, text, text, timestamptz) to authenticated;

-- 7.2 fn_list_incidents — staff / incidents.view / incidents.manage.
create or replace function fn_list_incidents(
  p_status text default null,
  p_limit int default 50,
  p_offset int default 0
)
returns table(
  incident_id uuid, student_id uuid, student_name text, type text, title text,
  description text, place text, occurred_at timestamptz, action_taken text,
  status text, reporter_name text, created_at timestamptz
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('incidents.view', v_school_id)
          or fn_has_permission('incidents.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select i.id, i.student_id, st.full_name, i.type, i.title, i.description,
         i.place, i.occurred_at, i.action_taken, i.status,
         (select p.full_name from profiles p where p.id = i.reported_by),
         i.created_at
  from incidents i
  join students st on st.id = i.student_id
  where i.school_id = v_school_id
    and (p_status is null or p_status = '' or i.status = p_status)
  order by i.created_at desc
  limit p_limit offset p_offset;
end;
$$;

revoke all on function fn_list_incidents(text, int, int) from public;
grant execute on function fn_list_incidents(text, int, int) to authenticated;

-- 7.3 fn_update_incident — close / add action taken. incidents.manage or staff.
create or replace function fn_update_incident(
  p_incident_id uuid,
  p_status text default null,
  p_action_taken text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select school_id into v_school_id from incidents where id = p_incident_id;
  if v_school_id is null then
    raise exception 'INVALID_INCIDENT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('incidents.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  update incidents set
    status = case when p_status in ('open', 'closed') then p_status else status end,
    action_taken = case when p_action_taken is not null
                        then nullif(trim(p_action_taken), '') else action_taken end
  where id = p_incident_id;

  perform fn_safe_audit(v_school_id, 'UPDATE_INCIDENT', 'incidents', p_incident_id,
    null, jsonb_build_object('status', p_status));
end;
$$;

revoke all on function fn_update_incident(uuid, text, text) from public;
grant execute on function fn_update_incident(uuid, text, text) to authenticated;

-- ============================================================================
-- SECTION 8 — NOTIFICATIONS (legacy notifications + notification_deliveries)
-- ============================================================================

-- Legacy phase2 schema: notifications(id, school_id NOT NULL, title NOT NULL,
-- body, created_at) and notification_deliveries(notification_id NOT NULL,
-- profile_id NOT NULL, read_at). We EXTEND notifications additively and use
-- notification_deliveries as the delivery/read mechanism — NO parallel
-- notification_reads table.

create table if not exists notifications (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  title text not null,
  body text,
  created_at timestamptz not null default now()
);

create table if not exists notification_deliveries (
  id uuid primary key default gen_random_uuid(),
  notification_id uuid not null references notifications(id) on delete cascade,
  profile_id uuid not null references profiles(id) on delete cascade,
  read_at timestamptz
);

-- Additive Phase-12 columns on the legacy notifications table:
alter table notifications add column if not exists type text not null default 'announcement';
alter table notifications add column if not exists target_role text;
alter table notifications add column if not exists target_profile_id uuid references profiles(id);
alter table notifications add column if not exists student_id uuid references students(id);
alter table notifications add column if not exists created_by uuid references profiles(id);

create index if not exists ix_notifications_school on notifications (school_id, created_at desc);
create index if not exists ix_notification_deliveries_profile on notification_deliveries (profile_id, read_at);

alter table notifications enable row level security;
alter table notification_deliveries enable row level security;

-- 8.1 fn_send_notification — staff or notifications.manage grant.
--     Creates ONE notifications row + delivery rows in notification_deliveries:
--     target_profile_id -> that member; target_role -> school members with that
--     role; student_id -> the student's parents; otherwise whole school.
create or replace function fn_send_notification(
  p_title text,
  p_body text default null,
  p_type text default 'announcement',
  p_target_role text default null,
  p_target_profile_id uuid default null,
  p_student_id uuid default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('notifications.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_title is null or trim(p_title) = '' then
    raise exception 'TITLE_REQUIRED';
  end if;

  insert into notifications
    (school_id, title, body, type, target_role, target_profile_id, student_id, created_by)
  values (
    v_school_id, trim(p_title), p_body,
    coalesce(nullif(trim(coalesce(p_type, '')), ''), 'announcement'),
    nullif(trim(coalesce(p_target_role, '')), ''),
    p_target_profile_id, p_student_id, auth.uid()
  )
  returning id into v_id;

  -- Deliveries (legacy notification_deliveries):
  if p_target_profile_id is not null then
    insert into notification_deliveries (notification_id, profile_id)
    select v_id, p_target_profile_id
    where exists (select 1 from user_roles ur
                  where ur.profile_id = p_target_profile_id and ur.school_id = v_school_id);
  elsif p_target_role is not null and trim(p_target_role) <> '' then
    insert into notification_deliveries (notification_id, profile_id)
    select distinct v_id, ur.profile_id
    from user_roles ur
    where ur.school_id = v_school_id
      and ur.role::text = lower(trim(p_target_role));   -- app_role enum is lowercase
  elsif p_student_id is not null then
    insert into notification_deliveries (notification_id, profile_id)
    select distinct v_id, pa.profile_id
    from parent_students ps
    join parents pa on pa.id = ps.parent_id and pa.deleted_at is null
    where ps.student_id = p_student_id;
  else
    insert into notification_deliveries (notification_id, profile_id)
    select distinct v_id, ur.profile_id
    from user_roles ur
    where ur.school_id = v_school_id;
  end if;

  perform fn_safe_audit(v_school_id, 'SEND_NOTIFICATION', 'notifications', v_id,
    null, jsonb_build_object('title', trim(p_title), 'type', p_type,
                             'target_role', p_target_role));

  return v_id;
end;
$$;

revoke all on function fn_send_notification(text, text, text, text, uuid, uuid) from public;
grant execute on function fn_send_notification(text, text, text, text, uuid, uuid) to authenticated;

-- 8.2 fn_list_my_notifications — deliveries addressed to the caller.
create or replace function fn_list_my_notifications(p_limit int default 50)
returns table(
  notification_id uuid, title text, body text, type text,
  created_at timestamptz, is_read boolean
)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;

  return query
  select n.id, n.title, n.body, n.type, n.created_at,
         (d.read_at is not null)
  from notification_deliveries d
  join notifications n on n.id = d.notification_id
  where d.profile_id = auth.uid()
  order by n.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_list_my_notifications(int) from public;
grant execute on function fn_list_my_notifications(int) to authenticated;

-- 8.3 fn_mark_notification_read — set read_at on the caller's delivery row.
create or replace function fn_mark_notification_read(p_notification_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;

  update notification_deliveries
  set read_at = now()
  where notification_id = p_notification_id
    and profile_id = auth.uid()
    and read_at is null;
end;
$$;

revoke all on function fn_mark_notification_read(uuid) from public;
grant execute on function fn_mark_notification_read(uuid) to authenticated;

-- 8.4 fn_unread_notifications_count — caller's unread deliveries.
create or replace function fn_unread_notifications_count()
returns bigint
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_count bigint;
begin
  if auth.uid() is null then
    return 0;
  end if;

  select count(*) into v_count
  from notification_deliveries d
  where d.profile_id = auth.uid() and d.read_at is null;

  return v_count;
end;
$$;

revoke all on function fn_unread_notifications_count() from public;
grant execute on function fn_unread_notifications_count() to authenticated;

-- ============================================================================
-- SECTION 9 — SCHOOL TRANSPORT (adopts the legacy phase2 tables; no parallel
-- transport schema)
-- ============================================================================

-- buses: legacy (id, school_id NOT NULL, plate_number text NOT NULL,
-- capacity int, is_active boolean NOT NULL default true).
create table if not exists buses (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  plate_number text not null,
  capacity int,
  is_active boolean not null default true
);

alter table buses add column if not exists plate_number text;
alter table buses add column if not exists capacity int;
alter table buses add column if not exists is_active boolean not null default true;
-- Additive Phase-12 columns (legacy table preserved untouched):
alter table buses add column if not exists code text;
alter table buses add column if not exists driver_id uuid references drivers(id);
alter table buses add column if not exists created_at timestamptz not null default now();

-- plate_number is NOT NULL in legacy: defensive no-op backfill (legacy rows
-- already satisfy the constraint, so this normally updates 0 rows).
update buses set plate_number = 'BUS-' || upper(substr(id::text, 1, 8))
where plate_number is null;

alter table buses enable row level security;

-- bus_routes: legacy (id, school_id NOT NULL, name NOT NULL).
create table if not exists bus_routes (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  name text not null
);
alter table bus_routes add column if not exists name text;
alter table bus_routes add column if not exists is_active boolean not null default true;
alter table bus_routes add column if not exists created_at timestamptz not null default now();
alter table bus_routes enable row level security;

-- bus_stops: legacy (id, school_id NOT NULL, name NOT NULL, latitude, longitude).
-- Stops link to routes ONLY via bus_route_stops — bus_stops has NO route_id.
create table if not exists bus_stops (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  name text not null,
  latitude double precision,
  longitude double precision
);
alter table bus_stops add column if not exists latitude double precision;
alter table bus_stops add column if not exists longitude double precision;
alter table bus_stops add column if not exists created_at timestamptz not null default now();
alter table bus_stops enable row level security;

-- bus_route_stops: ordered link table (route_id, stop_id, sequence_order).
create table if not exists bus_route_stops (
  id uuid primary key default gen_random_uuid(),
  route_id uuid not null references bus_routes(id) on delete cascade,
  stop_id uuid not null references bus_stops(id) on delete cascade,
  sequence_order int not null
);
alter table bus_route_stops add column if not exists sequence_order int;
create unique index if not exists ux_bus_route_stops_pair on bus_route_stops (route_id, stop_id);
alter table bus_route_stops enable row level security;

-- student_transport_assignments: legacy NOT NULL = student_id,
-- academic_year_id, route_id, bus_id, starts_on (default current_date),
-- is_active (default true).
create table if not exists student_transport_assignments (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  academic_year_id uuid not null references academic_years(id) on delete cascade,
  route_id uuid not null references bus_routes(id) on delete restrict,
  bus_id uuid not null references buses(id) on delete restrict,
  pickup_stop_id uuid references bus_stops(id),
  dropoff_stop_id uuid references bus_stops(id),
  starts_on date not null default current_date,
  ends_on date,
  is_active boolean not null default true
);
alter table student_transport_assignments add column if not exists ends_on date;
create index if not exists ix_sta_student_year
  on student_transport_assignments (student_id, academic_year_id, is_active);
alter table student_transport_assignments enable row level security;

-- bus_trips: legacy ENUM columns — direction trip_direction NOT NULL
-- ('TO_SCHOOL'/'TO_HOME'), status trip_status NOT NULL default 'PLANNED'
-- ('PLANNED'/'ACTIVE'/'COMPLETED'/'CANCELLED'), starts_at/ends_at timestamptz.
-- Lowercase 'pickup'/'dropoff'/'active'/... are mapped server-side and are
-- NEVER written to these enum columns.
create table if not exists bus_trips (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  bus_id uuid not null references buses(id) on delete restrict,
  driver_id uuid not null references drivers(id) on delete restrict,
  route_id uuid references bus_routes(id),
  direction trip_direction not null,
  status trip_status not null default 'PLANNED',
  starts_at timestamptz,
  ends_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists ix_bus_trips_driver on bus_trips (driver_id, status, created_at desc);
alter table bus_trips enable row level security;

-- bus_trip_students: per-trip SNAPSHOT — PK (trip_id, student_id),
-- boarded_at / dropped_at. Exactly ONE row per student per trip.
create table if not exists bus_trip_students (
  trip_id uuid not null references bus_trips(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  boarded_at timestamptz,
  dropped_at timestamptz,
  primary key (trip_id, student_id)
);
alter table bus_trip_students enable row level security;

-- bus_events: full EVENT HISTORY — event_type bus_event_type NOT NULL
-- ('BOARD'/'DROP_OFF'), source record_source NOT NULL default 'QR'
-- ('QR'/'MANUAL'), driver_id -> drivers(id).
create table if not exists bus_events (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references bus_trips(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  driver_id uuid references drivers(id),
  event_type bus_event_type not null,
  source record_source not null default 'QR',
  latitude double precision,
  longitude double precision,
  location_text text,
  notes text,
  created_at timestamptz not null default now()
);
create index if not exists ix_bus_events_trip on bus_events (trip_id, created_at);
alter table bus_events enable row level security;

-- 9.1 fn_create_bus — staff or transport.manage. plate_number always filled.
create or replace function fn_create_bus(
  p_code text,
  p_plate text default null,
  p_capacity integer default null,
  p_driver_id uuid default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_id uuid;
  v_plate text;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('transport.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_driver_id is not null and not exists (
    select 1 from drivers d
    where d.id = p_driver_id and d.school_id = v_school_id and d.deleted_at is null
  ) then
    raise exception 'INVALID_DRIVER';
  end if;

  -- plate_number is NOT NULL in the legacy schema: always fill it
  -- (explicit plate -> code -> generated fallback).
  v_plate := nullif(trim(coalesce(p_plate, '')), '');
  if v_plate is null then
    v_plate := nullif(trim(coalesce(p_code, '')), '');
  end if;
  if v_plate is null then
    v_plate := 'BUS-' || upper(substr(gen_random_uuid()::text, 1, 6));
  end if;

  insert into buses (school_id, plate_number, capacity, is_active, code, driver_id)
  values (v_school_id, v_plate, p_capacity, true,
          nullif(trim(coalesce(p_code, '')), ''), p_driver_id)
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'CREATE_BUS', 'buses', v_id,
    null, jsonb_build_object('code', p_code, 'plate', v_plate));

  return v_id;
end;
$$;

revoke all on function fn_create_bus(text, text, integer, uuid) from public;
grant execute on function fn_create_bus(text, text, integer, uuid) to authenticated;

-- 9.2 fn_list_buses — caller's school buses (code falls back to plate_number).
create or replace function fn_list_buses()
returns table(bus_id uuid, code text, plate text, capacity integer,
              is_active boolean, driver_id uuid, driver_name text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select b.id, coalesce(b.code, b.plate_number), b.plate_number, b.capacity, b.is_active,
         b.driver_id,
         (select p.full_name from drivers d join profiles p on p.id = d.profile_id
          where d.id = b.driver_id)
  from buses b
  where b.school_id = v_school_id
  order by coalesce(b.code, b.plate_number);
end;
$$;

revoke all on function fn_list_buses() from public;
grant execute on function fn_list_buses() to authenticated;

-- 9.3 fn_create_route — route + stops (bus_stops: school_id/name/lat/lng,
--     NO route_id) + ordered links in bus_route_stops (sequence_order).
create or replace function fn_create_route(p_name text, p_stops jsonb default '[]'::jsonb)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_route_id uuid;
  v_stop_id uuid;
  v_stop record;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('transport.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_name is null or trim(p_name) = '' then
    raise exception 'ROUTE_NAME_REQUIRED';
  end if;

  insert into bus_routes (school_id, name)
  values (v_school_id, trim(p_name))
  returning id into v_route_id;

  -- p_stops: jsonb array [{name, latitude?, longitude?}] — order preserved in
  -- bus_route_stops.sequence_order.
  for v_stop in
    select e.value ->> 'name' as stop_name,
           nullif(e.value ->> 'latitude', '')::double precision as lat,
           nullif(e.value ->> 'longitude', '')::double precision as lng,
           e.ordinality as seq
    from jsonb_array_elements(coalesce(p_stops, '[]'::jsonb)) with ordinality as e(value, ordinality)
  loop
    if nullif(trim(coalesce(v_stop.stop_name, '')), '') is null then
      continue;
    end if;
    insert into bus_stops (school_id, name, latitude, longitude)
    values (v_school_id, trim(v_stop.stop_name), v_stop.lat, v_stop.lng)
    returning id into v_stop_id;
    insert into bus_route_stops (route_id, stop_id, sequence_order)
    values (v_route_id, v_stop_id, v_stop.seq::int);
  end loop;

  perform fn_safe_audit(v_school_id, 'CREATE_ROUTE', 'bus_routes', v_route_id,
    null, jsonb_build_object('name', trim(p_name)));

  return v_route_id;
end;
$$;

revoke all on function fn_create_route(text, jsonb) from public;
grant execute on function fn_create_route(text, jsonb) to authenticated;

-- 9.4 fn_list_routes — routes with ordered stops (via bus_route_stops) and
--     active student counts.
create or replace function fn_list_routes()
returns table(route_id uuid, route_name text, is_active boolean,
              stops jsonb, student_count bigint)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select r.id, r.name, r.is_active,
         coalesce((
           select jsonb_agg(jsonb_build_object('stop_id', s.id, 'name', s.name)
                            order by rs.sequence_order)
           from bus_route_stops rs
           join bus_stops s on s.id = rs.stop_id
           where rs.route_id = r.id
         ), '[]'::jsonb),
         (select count(*) from student_transport_assignments sta
          where sta.route_id = r.id and sta.is_active)
  from bus_routes r
  where r.school_id = v_school_id
  order by r.name;
end;
$$;

revoke all on function fn_list_routes() from public;
grant execute on function fn_list_routes() to authenticated;

-- 9.5 fn_assign_student_transport — one ACTIVE assignment per student and
--     academic year: UPDATE it in place, never insert a second row. History
--     (inactive/ended assignments) is never touched. academic_year_id (NOT
--     NULL) is derived from the school's current year; starts_on defaults to
--     current_date; is_active = true.
create or replace function fn_assign_student_transport(
  p_student_id uuid,
  p_bus_id uuid default null,
  p_route_id uuid default null,
  p_pickup_stop_id uuid default null,
  p_dropoff_stop_id uuid default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_year_id uuid;
  v_existing uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('transport.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- route_id and bus_id are NOT NULL in legacy:
  if p_bus_id is null or p_route_id is null then
    raise exception 'TRANSPORT_BUS_ROUTE_REQUIRED';
  end if;
  if not exists (select 1 from buses where id = p_bus_id and school_id = v_school_id) then
    raise exception 'INVALID_BUS';
  end if;
  if not exists (select 1 from bus_routes where id = p_route_id and school_id = v_school_id) then
    raise exception 'INVALID_ROUTE';
  end if;
  if p_pickup_stop_id is not null and not exists (
    select 1 from bus_stops where id = p_pickup_stop_id and school_id = v_school_id
  ) then
    raise exception 'INVALID_STOP';
  end if;
  if p_dropoff_stop_id is not null and not exists (
    select 1 from bus_stops where id = p_dropoff_stop_id and school_id = v_school_id
  ) then
    raise exception 'INVALID_STOP';
  end if;

  -- academic_year_id NOT NULL: the school's current year (fallback: latest).
  select id into v_year_id from academic_years
  where school_id = v_school_id and is_current
  limit 1;
  if v_year_id is null then
    select id into v_year_id from academic_years
    where school_id = v_school_id
    order by created_at desc
    limit 1;
  end if;
  if v_year_id is null then
    raise exception 'NO_ACADEMIC_YEAR';
  end if;

  select id into v_existing
  from student_transport_assignments
  where student_id = p_student_id
    and academic_year_id = v_year_id
    and is_active
  limit 1;

  if v_existing is not null then
    -- Update the existing active row; never create a second row.
    update student_transport_assignments
    set bus_id = p_bus_id,
        route_id = p_route_id,
        pickup_stop_id = p_pickup_stop_id,
        dropoff_stop_id = p_dropoff_stop_id
    where id = v_existing;
  else
    insert into student_transport_assignments
      (student_id, academic_year_id, route_id, bus_id,
       pickup_stop_id, dropoff_stop_id, starts_on, is_active)
    values
      (p_student_id, v_year_id, p_route_id, p_bus_id,
       p_pickup_stop_id, p_dropoff_stop_id, current_date, true);
  end if;

  perform fn_safe_audit(v_school_id, 'ASSIGN_TRANSPORT', 'student_transport_assignments',
    coalesce(v_existing, p_student_id),
    null, jsonb_build_object('student_id', p_student_id, 'bus_id', p_bus_id,
                             'route_id', p_route_id, 'academic_year_id', v_year_id));
end;
$$;

revoke all on function fn_assign_student_transport(uuid, uuid, uuid, uuid, uuid) from public;
grant execute on function fn_assign_student_transport(uuid, uuid, uuid, uuid, uuid) to authenticated;

-- 9.6 fn_student_transport_info — the student's ACTIVE assignment.
create or replace function fn_student_transport_info(p_student_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_result jsonb;
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then raise exception 'INVALID_STUDENT'; end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('transport.view', v_school_id)
          or fn_is_parent_of(p_student_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  select jsonb_build_object(
    'bus_code', coalesce(b.code, b.plate_number), 'bus_plate', b.plate_number,
    'driver_name', (select p.full_name from drivers d join profiles p on p.id = d.profile_id
                    where d.id = b.driver_id),
    'route_name', r.name,
    'pickup_stop', (select rs.name from bus_stops rs where rs.id = sta.pickup_stop_id),
    'dropoff_stop', (select rs.name from bus_stops rs where rs.id = sta.dropoff_stop_id)
  ) into v_result
  from student_transport_assignments sta
  left join buses b on b.id = sta.bus_id
  left join bus_routes r on r.id = sta.route_id
  where sta.student_id = p_student_id
    and sta.is_active
  order by sta.starts_on desc
  limit 1;

  return v_result; -- null when the student has no active transport assignment
end;
$$;

revoke all on function fn_student_transport_info(uuid) from public;
grant execute on function fn_student_transport_info(uuid) to authenticated;

-- 9.7 fn_driver_context — the calling driver's driver row + assigned bus.
create or replace function fn_driver_context()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_driver drivers%rowtype;
  v_bus buses%rowtype;
begin
  select * into v_driver from drivers
  where profile_id = auth.uid() and deleted_at is null
  limit 1;
  if v_driver.id is null then
    return null;
  end if;

  select * into v_bus from buses
  where driver_id = v_driver.id and is_active = true
  limit 1;

  return jsonb_build_object(
    'driver_id', v_driver.id,
    'school_id', v_driver.school_id,
    'bus_id', v_bus.id,
    'bus_code', coalesce(v_bus.code, v_bus.plate_number),
    'bus_plate', v_bus.plate_number,
    'bus_capacity', v_bus.capacity
  );
end;
$$;

revoke all on function fn_driver_context() from public;
grant execute on function fn_driver_context() to authenticated;

-- 9.8 fn_start_trip — maps frontend 'pickup'/'dropoff' to the trip_direction
--     ENUM ('TO_SCHOOL'/'TO_HOME') BEFORE insert; status 'ACTIVE'; legacy
--     starts_at is filled (returned to the frontend as started_at alias).
--     Any still-ACTIVE trip of the same driver is auto-COMPLETED first.
create or replace function fn_start_trip(p_route_id uuid default null, p_direction text default 'pickup')
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_driver_id uuid;
  v_school_id uuid;
  v_bus_id uuid;
  v_direction trip_direction;
  v_trip_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  select d.id, d.school_id into v_driver_id, v_school_id
  from drivers d
  where d.profile_id = auth.uid() and d.deleted_at is null
  limit 1;
  if v_driver_id is null then
    raise exception 'NOT_A_DRIVER';
  end if;

  select b.id into v_bus_id from buses b
  where b.driver_id = v_driver_id and b.is_active
  limit 1;
  if v_bus_id is null then
    raise exception 'NO_BUS_ASSIGNED';
  end if;

  -- ENUM mapping (server-side; lowercase values never reach the enum column):
  v_direction := case lower(trim(coalesce(p_direction, 'pickup')))
                   when 'pickup'    then 'TO_SCHOOL'::trip_direction
                   when 'to_school' then 'TO_SCHOOL'::trip_direction
                   when 'dropoff'   then 'TO_HOME'::trip_direction
                   when 'to_home'   then 'TO_HOME'::trip_direction
                   else null
                 end;
  if v_direction is null then
    raise exception 'INVALID_DIRECTION';
  end if;

  if p_route_id is not null and not exists (
    select 1 from bus_routes where id = p_route_id and school_id = v_school_id
  ) then
    raise exception 'INVALID_ROUTE';
  end if;

  -- One active trip per driver: auto-complete previous ones.
  update bus_trips
  set status = 'COMPLETED'::trip_status, ends_at = now()
  where driver_id = v_driver_id and status = 'ACTIVE'::trip_status;

  insert into bus_trips (school_id, bus_id, driver_id, route_id, direction, status, starts_at)
  values (v_school_id, v_bus_id, v_driver_id, p_route_id,
          v_direction, 'ACTIVE'::trip_status, now())
  returning id into v_trip_id;

  perform fn_safe_audit(v_school_id, 'START_TRIP', 'bus_trips', v_trip_id,
    null, jsonb_build_object('direction', v_direction::text, 'bus_id', v_bus_id));

  return v_trip_id;
end;
$$;

revoke all on function fn_start_trip(uuid, text) from public;
grant execute on function fn_start_trip(uuid, text) to authenticated;

-- 9.9 fn_end_trip — status 'COMPLETED', legacy ends_at = now().
create or replace function fn_end_trip(p_trip_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_driver_id uuid;
  v_school_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  select d.id into v_driver_id from drivers d
  where d.profile_id = auth.uid() and d.deleted_at is null
  limit 1;
  if v_driver_id is null then
    raise exception 'NOT_A_DRIVER';
  end if;

  select t.school_id into v_school_id from bus_trips t
  where t.id = p_trip_id and t.driver_id = v_driver_id
    and t.status = 'ACTIVE'::trip_status;
  if v_school_id is null then
    raise exception 'INVALID_TRIP';
  end if;

  update bus_trips
  set status = 'COMPLETED'::trip_status, ends_at = now()
  where id = p_trip_id;

  perform fn_safe_audit(v_school_id, 'END_TRIP', 'bus_trips', p_trip_id, null, null);
end;
$$;

revoke all on function fn_end_trip(uuid) from public;
grant execute on function fn_end_trip(uuid) to authenticated;

-- 9.10 fn_record_trip_event — 'board'/'alight' mapped to bus_event_type ENUM
--      ('BOARD'/'DROP_OFF'). Snapshot (bus_trip_students: one row per
--      trip+student, PK-enforced) updated; history row added to bus_events
--      (source 'MANUAL' — recorded by the driver in the app).
create or replace function fn_record_trip_event(p_trip_id uuid, p_student_id uuid, p_event_type text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_trip bus_trips%rowtype;
  v_driver_id uuid;
  v_type bus_event_type;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  select * into v_trip from bus_trips where id = p_trip_id;
  if v_trip.id is null then
    raise exception 'INVALID_TRIP';
  end if;
  select d.id into v_driver_id from drivers d
  where d.profile_id = auth.uid() and d.deleted_at is null
  limit 1;
  if v_driver_id is null or v_trip.driver_id <> v_driver_id then
    raise exception 'PERMISSION_DENIED';
  end if;
  if not exists (select 1 from students s
                 where s.id = p_student_id and s.school_id = v_trip.school_id) then
    raise exception 'INVALID_STUDENT';
  end if;

  -- ENUM mapping (lowercase never reaches the enum column):
  v_type := case lower(trim(coalesce(p_event_type, '')))
              when 'board'    then 'BOARD'::bus_event_type
              when 'alight'   then 'DROP_OFF'::bus_event_type
              when 'drop_off' then 'DROP_OFF'::bus_event_type
              when 'dropoff'  then 'DROP_OFF'::bus_event_type
              else null
            end;
  if v_type is null then
    raise exception 'INVALID_EVENT_TYPE';
  end if;

  -- Snapshot: exactly one row per (trip, student) — PK enforced.
  insert into bus_trip_students (trip_id, student_id)
  values (p_trip_id, p_student_id)
  on conflict (trip_id, student_id) do nothing;

  if v_type = 'BOARD'::bus_event_type then
    update bus_trip_students
    set boarded_at = coalesce(boarded_at, now())
    where trip_id = p_trip_id and student_id = p_student_id;
  else
    update bus_trip_students
    set dropped_at = now()
    where trip_id = p_trip_id and student_id = p_student_id;
  end if;

  -- Event history (bus_events):
  insert into bus_events (trip_id, student_id, driver_id, event_type, source)
  values (p_trip_id, p_student_id, v_driver_id, v_type, 'MANUAL'::record_source);
end;
$$;

revoke all on function fn_record_trip_event(uuid, uuid, text) from public;
grant execute on function fn_record_trip_event(uuid, uuid, text) to authenticated;

-- 9.11 fn_get_active_trip — the calling driver's ACTIVE trip, with enum values
--      mapped BACK to the lowercase strings the frontend expects.
create or replace function fn_get_active_trip()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_driver_id uuid;
  v_trip record;
  v_events jsonb;
begin
  select d.id into v_driver_id from drivers d
  where d.profile_id = auth.uid() and d.deleted_at is null
  limit 1;
  if v_driver_id is null then
    return null;
  end if;

  select t.id, t.direction, t.status, t.starts_at, t.route_id,
         (select r.name from bus_routes r where r.id = t.route_id) as route_name,
         (select coalesce(b.code, b.plate_number) from buses b where b.id = t.bus_id) as bus_code
  into v_trip
  from bus_trips t
  where t.driver_id = v_driver_id and t.status = 'ACTIVE'::trip_status
  order by t.starts_at desc
  limit 1;

  if v_trip.id is null then
    return null;
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
           'student_id', be.student_id,
           'event_type', case when be.event_type = 'BOARD'::bus_event_type
                              then 'board' else 'alight' end,
           'created_at', be.created_at)
         order by be.created_at), '[]'::jsonb)
  into v_events
  from bus_events be
  where be.trip_id = v_trip.id;

  return jsonb_build_object(
    'trip_id', v_trip.id,
    'direction', case when v_trip.direction = 'TO_SCHOOL'::trip_direction
                      then 'pickup' else 'dropoff' end,
    'started_at', v_trip.starts_at,   -- legacy starts_at aliased for the UI
    'route_id', v_trip.route_id,
    'route_name', v_trip.route_name,
    'bus_code', v_trip.bus_code,
    'events', v_events
  );
end;
$$;

revoke all on function fn_get_active_trip() from public;
grant execute on function fn_get_active_trip() to authenticated;

-- 9.12 fn_list_bus_students — active assignments of the bus (+ per-trip
--      snapshot boarded_at / alighted_at = bus_trip_students.dropped_at).
create or replace function fn_list_bus_students(p_bus_id uuid, p_trip_id uuid default null)
returns table(student_id uuid, full_name text, student_number text,
              pickup_stop text, dropoff_stop text, boarded_at timestamptz, alighted_at timestamptz)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_ctx jsonb;
begin
  select school_id into v_school_id from buses where id = p_bus_id;
  if v_school_id is null then raise exception 'INVALID_BUS'; end if;

  v_ctx := fn_driver_context();
  if not (fn_is_school_member(v_school_id)
          or (v_ctx is not null and (v_ctx->>'bus_id')::uuid = p_bus_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select sta.student_id, s.full_name, s.student_number,
         (select rs.name from bus_stops rs where rs.id = sta.pickup_stop_id),
         (select rs.name from bus_stops rs where rs.id = sta.dropoff_stop_id),
         bts.boarded_at,
         bts.dropped_at   -- exposed to the UI as alighted_at
  from student_transport_assignments sta
  join students s on s.id = sta.student_id and s.deleted_at is null
  left join bus_trip_students bts
    on bts.trip_id = p_trip_id and bts.student_id = sta.student_id
  where sta.bus_id = p_bus_id
    and sta.is_active
  order by s.full_name;
end;
$$;

revoke all on function fn_list_bus_students(uuid, uuid) from public;
grant execute on function fn_list_bus_students(uuid, uuid) to authenticated;

-- 9.13 fn_my_trips — the calling driver's recent trips. Enum values are mapped
--      back to lowercase strings ('pickup'/'dropoff', 'completed'/'active'/...)
--      and starts_at/ends_at are aliased started_at/ended_at for the UI.
create or replace function fn_my_trips(p_limit int default 20)
returns table(trip_id uuid, trip_date date, direction text, status text,
              route_name text, started_at timestamptz, ended_at timestamptz, events_count bigint)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_ctx jsonb;
begin
  v_ctx := fn_driver_context();
  if v_ctx is null then return; end if;

  return query
  select t.id,
         coalesce(t.starts_at::date, t.created_at::date),
         case when t.direction = 'TO_SCHOOL'::trip_direction then 'pickup' else 'dropoff' end,
         lower(t.status::text),
         (select r.name from bus_routes r where r.id = t.route_id),
         t.starts_at, t.ends_at,
         (select count(*) from bus_events be where be.trip_id = t.id)
  from bus_trips t
  where t.driver_id = (v_ctx->>'driver_id')::uuid
  order by t.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_my_trips(int) from public;
grant execute on function fn_my_trips(int) to authenticated;

-- ============================================================================
-- SECTION 10 — FINANCE (adopts legacy payments + expenses/expense_categories)
-- ============================================================================

-- payments: legacy NOT NULL = student_id, month (int 1-12), year, amount_due,
-- amount_paid (default 0), status payment_status (default 'UNPAID';
-- 'PAID'/'PARTIAL'/'UNPAID'/'OVERDUE' — UPPERCASE only), plus
-- UNIQUE(student_id, month, year). Additive columns: school_id, fee_type,
-- receipt_no.
create table if not exists payments (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  month int not null check (month between 1 and 12),
  year int not null,
  amount_due numeric(10,2) not null check (amount_due >= 0),
  amount_paid numeric(10,2) not null default 0 check (amount_paid >= 0),
  status payment_status not null default 'UNPAID',
  method text,
  paid_on date,
  recorded_by uuid references profiles(id),
  notes text,
  created_at timestamptz not null default now(),
  unique (student_id, month, year)
);

alter table payments add column if not exists school_id uuid references schools(id);
alter table payments add column if not exists fee_type text;
alter table payments add column if not exists receipt_no text;

create index if not exists ix_payments_school on payments (school_id);
alter table payments enable row level security;

-- expense_categories / expenses: legacy (expenses.category_id ->
-- expense_categories(id), amount NOT NULL >= 0, expense_date, notes,
-- recorded_by). The frontend's free-text "category" is resolved to a
-- per-school expense_categories row (find-or-create).
create table if not exists expense_categories (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  name text not null
);
alter table expense_categories enable row level security;

create table if not exists expenses (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  category_id uuid references expense_categories(id),
  amount numeric(10,2) not null check (amount >= 0),
  expense_date date not null default current_date,
  notes text,
  recorded_by uuid references profiles(id),
  created_at timestamptz not null default now()
);
alter table expenses add column if not exists notes text;
alter table expenses enable row level security;

-- 10.1 fn_record_payment — UNIQUE(student_id, month, year) is NEVER broken:
--      if a row exists for that student+month+year it is UPDATED (amount_paid
--      incremented, UPPERCASE payment_status recomputed, paid_on set);
--      otherwise ONE row is inserted. month/year are derived from the payment
--      date. Old payments are never changed beyond this accumulation and are
--      never deleted.
create or replace function fn_record_payment(
  p_student_id uuid,
  p_fee_type text,
  p_amount_due numeric default 0,
  p_amount_paid numeric default 0,
  p_payment_date date default null,
  p_method text default null,
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
  v_date date;
  v_month int;
  v_year int;
  v_due numeric;
  v_paid numeric;
  v_pay payments%rowtype;
  v_new_due numeric;
  v_new_paid numeric;
  v_status payment_status;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then
    raise exception 'INVALID_STUDENT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('finance.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  v_date := coalesce(p_payment_date, current_date);
  v_month := extract(month from v_date)::int;   -- legacy month int 1-12 NOT NULL
  v_year := extract(year from v_date)::int;     -- legacy year int NOT NULL
  v_due := greatest(coalesce(p_amount_due, 0), 0);
  v_paid := greatest(coalesce(p_amount_paid, 0), 0);

  -- check-then-update/insert (no ON CONFLICT needed; the legacy UNIQUE exists)
  select * into v_pay from payments
  where student_id = p_student_id and month = v_month and year = v_year
  limit 1;

  if v_pay.id is not null then
    -- UPDATE the existing row: increment amount_paid, recompute status.
    v_new_due := case when v_due > 0 then v_due else v_pay.amount_due end;
    v_new_paid := v_pay.amount_paid + v_paid;
    v_status := case
                  when v_new_due > 0 and v_new_paid >= v_new_due then 'PAID'::payment_status
                  when v_new_paid > 0 then 'PARTIAL'::payment_status
                  else 'UNPAID'::payment_status
                end;
    update payments
    set amount_due = v_new_due,
        amount_paid = v_new_paid,
        status = v_status,
        paid_on = case when v_paid > 0 then v_date else paid_on end,
        method = coalesce(nullif(trim(coalesce(p_method, '')), ''), method),
        notes = coalesce(nullif(trim(coalesce(p_note, '')), ''), notes),
        fee_type = coalesce(nullif(trim(coalesce(p_fee_type, '')), ''), fee_type),
        school_id = coalesce(school_id, v_school_id),
        recorded_by = coalesce(recorded_by, auth.uid())
    where id = v_pay.id;
    v_id := v_pay.id;
  else
    v_status := case
                  when v_due > 0 and v_paid >= v_due then 'PAID'::payment_status
                  when v_paid > 0 then 'PARTIAL'::payment_status
                  else 'UNPAID'::payment_status
                end;
    insert into payments
      (student_id, month, year, amount_due, amount_paid, status,
       method, paid_on, recorded_by, notes, school_id, fee_type)
    values (
      p_student_id, v_month, v_year, v_due, v_paid, v_status,
      nullif(trim(coalesce(p_method, '')), ''),
      case when v_paid > 0 then v_date else null end,
      auth.uid(),
      nullif(trim(coalesce(p_note, '')), ''),
      v_school_id,
      nullif(trim(coalesce(p_fee_type, '')), '')
    )
    returning id into v_id;
  end if;

  -- Receipt number (additive column): generate once if empty.
  update payments
  set receipt_no = 'REC-' || upper(substr(v_id::text, 1, 8))
  where id = v_id and receipt_no is null;

  perform fn_safe_audit(v_school_id, 'RECORD_PAYMENT', 'payments', v_id,
    null, jsonb_build_object('student_id', p_student_id, 'month', v_month,
                             'year', v_year, 'amount_paid', v_paid,
                             'status', v_status::text));

  return v_id;
end;
$$;

revoke all on function fn_record_payment(uuid, text, numeric, numeric, date, text, text) from public;
grant execute on function fn_record_payment(uuid, text, numeric, numeric, date, text, text) to authenticated;

-- 10.2 fn_list_payments — school-isolated via the student's school (legacy
--      rows may have school_id NULL); payment_date = coalesce(paid_on,
--      created_at::date) alias for the UI.
create or replace function fn_list_payments(p_student_id uuid default null, p_limit int default 100)
returns table(payment_id uuid, student_id uuid, student_name text, fee_type text,
              amount_due numeric, amount_paid numeric, payment_date date,
              method text, receipt_no text, note text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('finance.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select fp.id, fp.student_id, s.full_name,
         coalesce(fp.fee_type, 'قسط ' || fp.month || '/' || fp.year),
         fp.amount_due, fp.amount_paid,
         coalesce(fp.paid_on, fp.created_at::date),
         fp.method, fp.receipt_no, fp.notes
  from payments fp
  join students s on s.id = fp.student_id
  where s.school_id = v_school_id
    and (p_student_id is null or fp.student_id = p_student_id)
  order by fp.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_list_payments(uuid, int) from public;
grant execute on function fn_list_payments(uuid, int) to authenticated;

-- 10.3 fn_record_expense — resolves the free-text category to a per-school
--      expense_categories row (find-or-create) and fills legacy columns
--      (amount, expense_date, notes, recorded_by).
create or replace function fn_record_expense(
  p_category text,
  p_amount numeric,
  p_expense_date date default null,
  p_description text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_cat_id uuid;
  v_id uuid;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('finance.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_category is null or trim(p_category) = '' then
    raise exception 'EXPENSE_CATEGORY_REQUIRED';
  end if;
  if p_amount is null or p_amount <= 0 then
    raise exception 'INVALID_AMOUNT';
  end if;

  -- find-or-create the category (check-then-insert; legacy has no UNIQUE).
  select id into v_cat_id from expense_categories
  where school_id = v_school_id and name = trim(p_category)
  limit 1;
  if v_cat_id is null then
    insert into expense_categories (school_id, name)
    values (v_school_id, trim(p_category))
    returning id into v_cat_id;
  end if;

  insert into expenses (school_id, category_id, amount, expense_date, notes, recorded_by)
  values (v_school_id, v_cat_id, p_amount,
          coalesce(p_expense_date, current_date),
          nullif(trim(coalesce(p_description, '')), ''),
          auth.uid())
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'RECORD_EXPENSE', 'expenses', v_id,
    null, jsonb_build_object('category', trim(p_category), 'amount', p_amount));

  return v_id;
end;
$$;

revoke all on function fn_record_expense(text, numeric, date, text) from public;
grant execute on function fn_record_expense(text, numeric, date, text) to authenticated;

-- 10.4 fn_list_expenses — category name resolved from expense_categories;
--      description = legacy notes.
create or replace function fn_list_expenses(p_limit int default 100)
returns table(expense_id uuid, category text, amount numeric, expense_date date,
              description text, recorder_name text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('finance.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select e.id, coalesce(ec.name, '—'), e.amount, e.expense_date, e.notes,
         (select p.full_name from profiles p where p.id = e.recorded_by)
  from expenses e
  left join expense_categories ec on ec.id = e.category_id
  where e.school_id = v_school_id
  order by e.expense_date desc, e.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_list_expenses(int) from public;
grant execute on function fn_list_expenses(int) to authenticated;

-- 10.5 fn_finance_summary — totals over legacy columns.
create or replace function fn_finance_summary(p_from date default null, p_to date default null)
returns table(total_due numeric, total_paid numeric, total_expenses numeric, net numeric)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_from date;
  v_to date;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('finance.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  v_from := coalesce(p_from, date_trunc('month', current_date)::date);
  v_to := coalesce(p_to, current_date);

  return query
  select
    coalesce((select sum(p.amount_due) from payments p
              join students s on s.id = p.student_id
              where s.school_id = v_school_id
                and p.created_at::date between v_from and v_to), 0),
    coalesce((select sum(p.amount_paid) from payments p
              join students s on s.id = p.student_id
              where s.school_id = v_school_id
                and coalesce(p.paid_on, p.created_at::date) between v_from and v_to), 0),
    coalesce((select sum(e.amount) from expenses e
              where e.school_id = v_school_id
                and e.expense_date between v_from and v_to), 0),
    coalesce((select sum(p.amount_paid) from payments p
              join students s on s.id = p.student_id
              where s.school_id = v_school_id
                and coalesce(p.paid_on, p.created_at::date) between v_from and v_to), 0)
    - coalesce((select sum(e.amount) from expenses e
                where e.school_id = v_school_id
                  and e.expense_date between v_from and v_to), 0);
end;
$$;

revoke all on function fn_finance_summary(date, date) from public;
grant execute on function fn_finance_summary(date, date) to authenticated;

-- ============================================================================
-- SECTION 11 — CLASS SCHEDULE (adopts legacy timetables + timetable_entries;
-- no parallel class_schedule table)
-- ============================================================================

-- timetables: legacy (id, school_id NOT NULL, academic_year_id NOT NULL,
-- name NOT NULL default 'Default', created_at).
create table if not exists timetables (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  academic_year_id uuid not null references academic_years(id) on delete cascade,
  name text not null default 'Default',
  created_at timestamptz not null default now()
);
alter table timetables enable row level security;

-- timetable_entries: legacy NOT NULL = timetable_id, class_id, subject_id,
-- teacher_id, weekday (smallint 1-7 where 1=Sunday), starts_at, ends_at (time).
-- Additive Phase-12 column: period (nullable — legacy rows stay untouched).
create table if not exists timetable_entries (
  id uuid primary key default gen_random_uuid(),
  timetable_id uuid not null references timetables(id) on delete cascade,
  class_id uuid not null references classes(id) on delete cascade,
  subject_id uuid not null references subjects(id) on delete cascade,
  teacher_id uuid not null references teachers(id) on delete cascade,
  weekday smallint not null check (weekday between 1 and 7),
  starts_at time not null,
  ends_at time not null
);
alter table timetable_entries add column if not exists period smallint;
alter table timetable_entries enable row level security;

-- 11.1 fn_set_class_schedule — replaces ONLY this class's entries inside the
--      school's timetable for the class's academic year (targeted delete of
--      rows this function manages; nothing else is touched).
--      p_entries: jsonb [{weekday (0=Sunday..6, JS), period, subject_id,
--      teacher_id?}]. weekday is mapped +1 to the legacy 1=Sunday..7 range;
--      starts_at/ends_at are derived from period (45-minute slots from 07:00).
create or replace function fn_set_class_schedule(p_class_id uuid, p_entries jsonb)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_year_id uuid;
  v_tt_id uuid;
  v_entry record;
  v_weekday smallint;
  v_period smallint;
  v_subject uuid;
  v_teacher uuid;
  v_start time;
  v_count int := 0;
begin
  if auth.uid() is null then
    raise exception 'NOT_AUTHENTICATED';
  end if;
  select c.school_id, c.academic_year_id into v_school_id, v_year_id
  from classes c where c.id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('schedule.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- find-or-create the school's timetable for the class's academic year.
  select t.id into v_tt_id from timetables t
  where t.school_id = v_school_id and t.academic_year_id = v_year_id
  order by t.created_at
  limit 1;
  if v_tt_id is null then
    insert into timetables (school_id, academic_year_id, name)
    values (v_school_id, v_year_id, 'Default')
    returning id into v_tt_id;
  end if;

  -- Replace only THIS class's entries in that timetable.
  delete from timetable_entries
  where timetable_id = v_tt_id and class_id = p_class_id;

  for v_entry in
    select value from jsonb_array_elements(coalesce(p_entries, '[]'::jsonb))
  loop
    -- Frontend weekday: 0=Sunday..6=Saturday -> legacy 1=Sunday..7=Saturday.
    v_weekday := (nullif(v_entry.value ->> 'weekday', '')::smallint + 1);
    if v_weekday is null or v_weekday < 1 or v_weekday > 7 then
      continue;
    end if;

    v_subject := nullif(v_entry.value ->> 'subject_id', '')::uuid;
    if v_subject is null then
      raise exception 'SCHEDULE_SUBJECT_REQUIRED';   -- subject_id NOT NULL
    end if;
    if not exists (select 1 from subjects s
                   where s.id = v_subject and s.school_id = v_school_id) then
      raise exception 'INVALID_SUBJECT';
    end if;

    -- teacher_id is NOT NULL in legacy: entry teacher, else class teacher.
    v_teacher := coalesce(
      nullif(v_entry.value ->> 'teacher_id', '')::uuid,
      (select c.teacher_id from classes c where c.id = p_class_id)
    );
    if v_teacher is null then
      raise exception 'SCHEDULE_TEACHER_REQUIRED';
    end if;
    if not exists (select 1 from teachers t
                   where t.id = v_teacher and t.school_id = v_school_id
                     and t.deleted_at is null) then
      raise exception 'INVALID_TEACHER';
    end if;

    v_period := coalesce(nullif(v_entry.value ->> 'period', '')::smallint, 1);
    v_start := time '07:00' + ((v_period - 1) * interval '45 minutes');

    insert into timetable_entries
      (timetable_id, class_id, subject_id, teacher_id, weekday, starts_at, ends_at, period)
    values
      (v_tt_id, p_class_id, v_subject, v_teacher, v_weekday,
       v_start, v_start + interval '45 minutes', v_period);
    v_count := v_count + 1;
  end loop;

  perform fn_safe_audit(v_school_id, 'SET_CLASS_SCHEDULE', 'timetable_entries', p_class_id,
    null, jsonb_build_object('entries', v_count));

  return v_count;
end;
$$;

revoke all on function fn_set_class_schedule(uuid, jsonb) from public;
grant execute on function fn_set_class_schedule(uuid, jsonb) to authenticated;

-- 11.2 fn_get_class_schedule — legacy weekday mapped back to 0=Sunday..6.
create or replace function fn_get_class_schedule(p_class_id uuid)
returns table(weekday smallint, period smallint, subject_name text, teacher_name text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  select c.school_id into v_school_id from classes c where c.id = p_class_id;
  if v_school_id is null then
    raise exception 'INVALID_CLASS';
  end if;
  if not fn_is_school_member(v_school_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select (te.weekday - 1)::smallint,               -- back to JS 0=Sunday..6
         coalesce(te.period, 1)::smallint,
         su.name,
         (select p.full_name from teachers t join profiles p on p.id = t.profile_id
          where t.id = te.teacher_id)
  from timetable_entries te
  join subjects su on su.id = te.subject_id
  where te.class_id = p_class_id
  order by te.weekday, coalesce(te.period, 1);
end;
$$;

revoke all on function fn_get_class_schedule(uuid) from public;
grant execute on function fn_get_class_schedule(uuid) to authenticated;

-- ============================================================================
-- SECTION 12 — STUDENT DETAIL & PARENT PORTAL
-- ============================================================================

-- 12.1 fn_get_student_full — consolidated student file.
--      Staff/members of the school or the parent of the student.
create or replace function fn_get_student_full(p_student_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_result jsonb;
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then raise exception 'INVALID_STUDENT'; end if;
  if not (fn_is_school_member(v_school_id) or fn_is_parent_of(p_student_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  select jsonb_build_object(
    'student_id', st.id,
    'full_name', st.full_name,
    'student_number', st.student_number,
    'photo_url', st.photo_url,
    'birth_date', st.birth_date,
    'gender', st.gender,
    'is_active', st.deleted_at is null,
    'class_name', (select c.name from student_enrollments se
                   join classes c on c.id = se.class_id
                   where se.student_id = st.id and se.status = 'ACTIVE' limit 1),
    'level', (select c.level from student_enrollments se
              join classes c on c.id = se.class_id
              where se.student_id = st.id and se.status = 'ACTIVE' limit 1),
    'year_name', (select ay.label from student_enrollments se
                  join classes c on c.id = se.class_id
                  join academic_years ay on ay.id = c.academic_year_id
                  where se.student_id = st.id and se.status = 'ACTIVE' limit 1),
    'badge_status', (select sb.status::text from student_badges sb
                     where sb.student_id = st.id order by sb.created_at desc limit 1),
    'attendance_30d', (select jsonb_build_object(
                         'present', count(*) filter (where ar.status = 'present'),
                         'absent', count(*) filter (where ar.status = 'absent'),
                         'late', count(*) filter (where ar.status = 'late'),
                         'excused', count(*) filter (where ar.status = 'excused'))
                       from attendance_records ar
                       where ar.student_id = st.id
                         and ar.att_date >= current_date - 30),
    'open_incidents', (select count(*) from incidents i
                       where i.student_id = st.id and i.status = 'open'),
    'parents', coalesce((select jsonb_agg(jsonb_build_object(
                   'name', p.full_name, 'phone', p.phone, 'relationship', ps.relationship))
                 from parent_students ps
                 join parents pa on pa.id = ps.parent_id
                 join profiles p on p.id = pa.profile_id
                 where ps.student_id = st.id), '[]'::jsonb),
    'transport', fn_student_transport_info(st.id)
  ) into v_result
  from students st
  where st.id = p_student_id;

  return v_result;
end;
$$;

revoke all on function fn_get_student_full(uuid) from public;
grant execute on function fn_get_student_full(uuid) to authenticated;

-- 12.2 fn_my_children — the calling parent's linked children.
create or replace function fn_my_children()
returns table(student_id uuid, full_name text, student_number text, photo_url text,
              class_name text, level text, relationship text)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  return query
  select st.id, st.full_name, st.student_number, st.photo_url,
         (select c.name from student_enrollments se
          join classes c on c.id = se.class_id
          where se.student_id = st.id and se.status = 'ACTIVE' limit 1),
         (select c.level from student_enrollments se
          join classes c on c.id = se.class_id
          where se.student_id = st.id and se.status = 'ACTIVE' limit 1),
         ps.relationship
  from parent_students ps
  join parents pa on pa.id = ps.parent_id and pa.deleted_at is null
  join students st on st.id = ps.student_id and st.deleted_at is null
  where pa.profile_id = auth.uid()
  order by st.full_name;
end;
$$;

revoke all on function fn_my_children() from public;
grant execute on function fn_my_children() to authenticated;

-- 12.3 fn_child_payments — parent's view of one child's fee payments.
create or replace function fn_child_payments(p_student_id uuid)
returns table(fee_type text, amount_due numeric, amount_paid numeric, payment_date date, receipt_no text)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
  if not fn_is_parent_of(p_student_id) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- Legacy payments: month/year NOT NULL; payment_date alias = paid_on (or
  -- creation date); fee_type alias when the additive column is empty.
  return query
  select coalesce(fp.fee_type, 'قسط ' || fp.month || '/' || fp.year),
         fp.amount_due, fp.amount_paid,
         coalesce(fp.paid_on, fp.created_at::date),
         fp.receipt_no
  from payments fp
  where fp.student_id = p_student_id
  order by fp.year desc, fp.month desc
  limit 100;
end;
$$;

revoke all on function fn_child_payments(uuid) from public;
grant execute on function fn_child_payments(uuid) to authenticated;

-- ============================================================================
-- SECTION 13 — SCHOOL DASHBOARD (director/admin home)
-- ============================================================================

create or replace function fn_get_school_dashboard()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not fn_is_school_member(v_school_id) then raise exception 'PERMISSION_DENIED'; end if;

  return jsonb_build_object(
    'school_id', v_school_id,
    'students', (select count(*) from students where school_id = v_school_id and deleted_at is null),
    'teachers', (select count(*) from teachers where school_id = v_school_id and deleted_at is null),
    'guards', (select count(*) from guards where school_id = v_school_id),
    'drivers', (select count(*) from drivers where school_id = v_school_id and deleted_at is null),
    'parents', (select count(*) from parents where school_id = v_school_id and deleted_at is null),
    'classes', (select count(*) from classes c join academic_years ay on ay.id = c.academic_year_id
                where c.school_id = v_school_id and ay.is_current and not c.is_disabled),
    'academic_years', (select count(*) from academic_years where school_id = v_school_id),
    'buses', (select count(*) from buses where school_id = v_school_id and is_active),
    'attendance_today', coalesce((select row_to_json(t) from fn_school_attendance_today() t),
                                 '{"present":0,"absent":0,"late":0,"excused":0,"total_marked":0}'::json),
    'payments_month', coalesce((select sum(p.amount_paid) from payments p
                        join students st on st.id = p.student_id
                        where st.school_id = v_school_id
                          and coalesce(p.paid_on, p.created_at::date) >= date_trunc('month', current_date)::date), 0),
    'expenses_month', coalesce((select sum(amount) from expenses
                        where school_id = v_school_id
                          and expense_date >= date_trunc('month', current_date)::date), 0),
    'open_incidents', (select count(*) from incidents where school_id = v_school_id and status = 'open'),
    'notifications_total', (select count(*) from notifications where school_id = v_school_id)
  );
end;
$$;

revoke all on function fn_get_school_dashboard() from public;
grant execute on function fn_get_school_dashboard() to authenticated;

-- ============================================================================
-- SECTION 14 — SCHOOL AUDIT (director/admin sees their own school's log)
-- ============================================================================

create or replace function fn_get_school_audit(p_limit int default 50, p_offset int default 0)
returns table(audit_id uuid, action text, entity text, entity_id uuid,
              actor_name text, created_at timestamptz)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('audit.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select al.id, al.action, al.entity, al.entity_id,
         (select p.full_name from profiles p where p.id = al.actor_id),
         al.created_at
  from audit_logs al
  where al.school_id = v_school_id
  order by al.created_at desc
  limit p_limit offset p_offset;
end;
$$;

revoke all on function fn_get_school_audit(int, int) from public;
grant execute on function fn_get_school_audit(int, int) to authenticated;

-- ============================================================================
-- END OF PHASE 12 COMPLETE PLATFORM MIGRATION (v5)
-- ============================================================================
