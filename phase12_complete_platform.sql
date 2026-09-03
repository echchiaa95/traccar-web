-- ============================================================================
-- supabase/migrations/phase12_complete_platform.sql
-- PHASE 12 — Complete school-management platform upgrade.
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

  if exists (select 1 from academic_years
             where school_id = v_school_id and name = trim(p_name)) then
    raise exception 'ACADEMIC_YEAR_EXISTS';
  end if;

  if p_is_current then
    update academic_years set is_current = false
    where school_id = v_school_id and is_current = true;
  end if;

  -- The first year of a school becomes current automatically.
  insert into academic_years (school_id, name, is_current)
  values (
    v_school_id,
    trim(p_name),
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
    if exists (select 1 from academic_years
               where school_id = v_school_id and name = trim(p_name) and id <> p_year_id) then
      raise exception 'ACADEMIC_YEAR_EXISTS';
    end if;
    update academic_years set name = trim(p_name) where id = p_year_id;
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
    ay.name, c.teacher_id,
    (select p.full_name from teachers t join profiles p on p.id = t.profile_id
     where t.id = c.teacher_id),
    (select count(*) from student_enrollments se
     where se.class_id = c.id and se.status = 'ACTIVE')
  from classes c
  join academic_years ay on ay.id = c.academic_year_id
  where c.school_id = v_school_id
    and (p_academic_year_id is null or c.academic_year_id = p_academic_year_id)
  order by ay.is_current desc, ay.name desc, c.name;
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
  select ay.id, ay.name, ay.is_current, ay.is_disabled,
    (select count(*) from classes c where c.academic_year_id = ay.id)
  from academic_years ay
  where ay.school_id = v_school_id
  order by ay.is_current desc, ay.name desc;
end;
$$;

revoke all on function fn_list_my_academic_years() from public;
grant execute on function fn_list_my_academic_years() to authenticated;

-- ============================================================================
-- SECTION 4 — SUBJECTS
-- ============================================================================

create table if not exists subjects (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now(),
  unique (school_id, name)
);

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

  insert into subjects (school_id, name) values (v_school_id, trim(p_name))
  on conflict (school_id, name) do update set name = excluded.name
  returning id into v_id;

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

create table if not exists student_grades (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  class_id uuid references classes(id) on delete set null,
  subject_id uuid references subjects(id) on delete set null,
  period text,
  grade_type text not null default 'تقويم',
  score numeric not null,
  max_score numeric not null default 20,
  note text,
  teacher_id uuid references profiles(id),
  created_at timestamptz not null default now()
);

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
          or fn_has_permission('grades.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_score is null or p_score < 0 then
    raise exception 'INVALID_SCORE';
  end if;

  insert into student_grades
    (school_id, student_id, class_id, subject_id, period, grade_type, score, max_score, note, teacher_id)
  values (
    v_school_id, p_student_id, p_class_id, p_subject_id,
    nullif(trim(coalesce(p_period, '')), ''),
    nullif(trim(coalesce(p_grade_type, '')), 'تقويم'),
    p_score, coalesce(p_max_score, 20),
    nullif(trim(coalesce(p_note, '')), ''),
    auth.uid()
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
         (select p.full_name from profiles p where p.id = g.teacher_id),
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
-- SECTION 8 — NOTIFICATIONS
-- ============================================================================

create table if not exists notifications (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  title text not null,
  body text,
  type text not null default 'announcement',  -- absence / late / grade / announcement / transport / payment / incident
  target_role text,                            -- null = whole school
  target_profile_id uuid references profiles(id), -- null = role/broadcast
  student_id uuid references students(id),
  created_by uuid references profiles(id),
  created_at timestamptz not null default now()
);

create table if not exists notification_reads (
  notification_id uuid not null references notifications(id) on delete cascade,
  profile_id uuid not null references profiles(id) on delete cascade,
  read_at timestamptz not null default now(),
  primary key (notification_id, profile_id)
);

create index if not exists ix_notifications_school on notifications (school_id, created_at desc);

alter table notifications enable row level security;
alter table notification_reads enable row level security;

-- 8.1 fn_send_notification — staff or notifications.manage grant.
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
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    raise exception 'NO_SCHOOL_CONTEXT';
  end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('notifications.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_title is null or trim(p_title) = '' then
    raise exception 'NOTIFICATION_TITLE_REQUIRED';
  end if;

  insert into notifications (school_id, title, body, type, target_role, target_profile_id, student_id, created_by)
  values (v_school_id, trim(p_title), nullif(trim(coalesce(p_body, '')), ''),
          nullif(trim(coalesce(p_type, '')), 'announcement'),
          nullif(trim(coalesce(p_target_role, '')), ''),
          p_target_profile_id, p_student_id, auth.uid())
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'SEND_NOTIFICATION', 'notifications', v_id,
    null, jsonb_build_object('title', trim(p_title), 'type', p_type));

  return v_id;
end;
$$;

revoke all on function fn_send_notification(text, text, text, text, uuid, uuid) from public;
grant execute on function fn_send_notification(text, text, text, text, uuid, uuid) to authenticated;

-- 8.2 fn_list_my_notifications — broadcast + my role + personally targeted.
create or replace function fn_list_my_notifications(p_limit int default 50)
returns table(
  notification_id uuid, title text, body text, type text,
  created_at timestamptz, is_read boolean, student_name text
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_roles text[];
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then
    return;
  end if;

  select array_agg(role::text) into v_roles
  from user_roles
  where profile_id = auth.uid() and school_id = v_school_id;

  return query
  select n.id, n.title, n.body, n.type, n.created_at,
         exists (select 1 from notification_reads nr
                 where nr.notification_id = n.id and nr.profile_id = auth.uid()),
         (select st.full_name from students st where st.id = n.student_id)
  from notifications n
  where n.school_id = v_school_id
    and (n.target_profile_id = auth.uid()
         or (n.target_profile_id is null and n.target_role is null)
         or (n.target_profile_id is null and n.target_role = any (coalesce(v_roles, '{}'))))
  order by n.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_list_my_notifications(int) from public;
grant execute on function fn_list_my_notifications(int) to authenticated;

create or replace function fn_mark_notification_read(p_notification_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into notification_reads (notification_id, profile_id)
  values (p_notification_id, auth.uid())
  on conflict do nothing;
end;
$$;

revoke all on function fn_mark_notification_read(uuid) from public;
grant execute on function fn_mark_notification_read(uuid) to authenticated;

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
  select count(*) into v_count
  from fn_list_my_notifications(200) n
  where not n.is_read;
  return v_count;
end;
$$;

revoke all on function fn_unread_notifications_count() from public;
grant execute on function fn_unread_notifications_count() to authenticated;

-- ============================================================================
-- SECTION 9 — SCHOOL TRANSPORT (buses, routes, stops, trips, boarding)
-- ============================================================================

create table if not exists buses (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  code text not null,
  plate text,
  capacity integer,
  driver_id uuid references drivers(id),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  unique (school_id, code)
);

create table if not exists transport_routes (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  name text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  unique (school_id, name)
);

create table if not exists route_stops (
  id uuid primary key default gen_random_uuid(),
  route_id uuid not null references transport_routes(id) on delete cascade,
  name text not null,
  sort_order integer not null default 0
);

create table if not exists student_transport (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  bus_id uuid references buses(id),
  route_id uuid references transport_routes(id),
  pickup_stop_id uuid references route_stops(id),
  dropoff_stop_id uuid references route_stops(id),
  created_at timestamptz not null default now(),
  unique (student_id)
);

create table if not exists trips (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  bus_id uuid not null references buses(id),
  route_id uuid references transport_routes(id),
  driver_id uuid references drivers(id),
  trip_date date not null default current_date,
  direction text not null default 'pickup' check (direction in ('pickup', 'dropoff')),
  status text not null default 'active' check (status in ('planned', 'active', 'completed', 'cancelled')),
  started_at timestamptz not null default now(),
  ended_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists trip_events (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references trips(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  event_type text not null check (event_type in ('board', 'alight')),
  recorded_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  unique (trip_id, student_id, event_type)
);

alter table buses enable row level security;
alter table transport_routes enable row level security;
alter table route_stops enable row level security;
alter table student_transport enable row level security;
alter table trips enable row level security;
alter table trip_events enable row level security;

-- 9.1 fn_create_bus — transport.manage or staff.
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
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('transport.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_code is null or trim(p_code) = '' then raise exception 'BUS_CODE_REQUIRED'; end if;
  if p_driver_id is not null and not exists (
    select 1 from drivers where id = p_driver_id and school_id = v_school_id and deleted_at is null
  ) then raise exception 'INVALID_DRIVER'; end if;

  insert into buses (school_id, code, plate, capacity, driver_id)
  values (v_school_id, trim(p_code), nullif(trim(coalesce(p_plate, '')), ''), p_capacity, p_driver_id)
  on conflict (school_id, code) do update
    set plate = excluded.plate, capacity = excluded.capacity,
        driver_id = excluded.driver_id, is_active = true
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'SAVE_BUS', 'buses', v_id,
    null, jsonb_build_object('code', trim(p_code)));
  return v_id;
end;
$$;

revoke all on function fn_create_bus(text, text, integer, uuid) from public;
grant execute on function fn_create_bus(text, text, integer, uuid) to authenticated;

-- 9.2 fn_list_buses — school members (drivers see their own bus too).
create or replace function fn_list_buses()
returns table(bus_id uuid, code text, plate text, capacity integer, is_active boolean,
              driver_id uuid, driver_name text, student_count bigint)
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

  return query
  select b.id, b.code, b.plate, b.capacity, b.is_active, b.driver_id,
         (select p.full_name from drivers d join profiles p on p.id = d.profile_id
          where d.id = b.driver_id),
         (select count(*) from student_transport st where st.bus_id = b.id)
  from buses b
  where b.school_id = v_school_id
  order by b.code;
end;
$$;

revoke all on function fn_list_buses() from public;
grant execute on function fn_list_buses() to authenticated;

-- 9.3 fn_create_route — with ordered stops. p_stops: jsonb array of names or
--     {"name": ...} objects.
create or replace function fn_create_route(p_name text, p_stops jsonb default '[]'::jsonb)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_id uuid;
  v_stop jsonb;
  v_order integer := 0;
  v_stop_name text;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('transport.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_name is null or trim(p_name) = '' then raise exception 'ROUTE_NAME_REQUIRED'; end if;

  insert into transport_routes (school_id, name) values (v_school_id, trim(p_name))
  on conflict (school_id, name) do update set is_active = true
  returning id into v_id;

  if p_stops is not null and jsonb_typeof(p_stops) = 'array' then
    for v_stop in select * from jsonb_array_elements(p_stops)
    loop
      v_stop_name := coalesce(nullif(trim(coalesce(v_stop->>'name', '')), ''),
                              nullif(trim(v_stop #>> '{}'), ''));
      if v_stop_name is not null then
        insert into route_stops (route_id, name, sort_order) values (v_id, v_stop_name, v_order);
        v_order := v_order + 1;
      end if;
    end loop;
  end if;

  perform fn_safe_audit(v_school_id, 'SAVE_ROUTE', 'transport_routes', v_id,
    null, jsonb_build_object('name', trim(p_name)));
  return v_id;
end;
$$;

revoke all on function fn_create_route(text, jsonb) from public;
grant execute on function fn_create_route(text, jsonb) to authenticated;

-- 9.4 fn_list_routes — routes with their ordered stops.
create or replace function fn_list_routes()
returns table(route_id uuid, route_name text, is_active boolean, stops jsonb, student_count bigint)
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

  return query
  select r.id, r.name, r.is_active,
         coalesce((select jsonb_agg(jsonb_build_object('stop_id', rs.id, 'name', rs.name)
                                  order by rs.sort_order)
                   from route_stops rs where rs.route_id = r.id), '[]'::jsonb),
         (select count(*) from student_transport st where st.route_id = r.id)
  from transport_routes r
  where r.school_id = v_school_id
  order by r.name;
end;
$$;

revoke all on function fn_list_routes() from public;
grant execute on function fn_list_routes() to authenticated;

-- 9.5 fn_assign_student_transport — upsert the student's bus/route/stops.
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
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then raise exception 'INVALID_STUDENT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('transport.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  if p_bus_id is not null and not exists (select 1 from buses where id = p_bus_id and school_id = v_school_id) then
    raise exception 'INVALID_BUS';
  end if;
  if p_route_id is not null and not exists (select 1 from transport_routes where id = p_route_id and school_id = v_school_id) then
    raise exception 'INVALID_ROUTE';
  end if;

  insert into student_transport (school_id, student_id, bus_id, route_id, pickup_stop_id, dropoff_stop_id)
  values (v_school_id, p_student_id, p_bus_id, p_route_id, p_pickup_stop_id, p_dropoff_stop_id)
  on conflict (student_id) do update
    set bus_id = excluded.bus_id, route_id = excluded.route_id,
        pickup_stop_id = excluded.pickup_stop_id, dropoff_stop_id = excluded.dropoff_stop_id;

  perform fn_safe_audit(v_school_id, 'ASSIGN_TRANSPORT', 'student_transport', p_student_id,
    null, jsonb_build_object('bus_id', p_bus_id, 'route_id', p_route_id));
end;
$$;

revoke all on function fn_assign_student_transport(uuid, uuid, uuid, uuid, uuid) from public;
grant execute on function fn_assign_student_transport(uuid, uuid, uuid, uuid, uuid) to authenticated;

-- 9.6 fn_student_transport_info — one student's assignment (staff or parent).
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
    'bus_code', b.code, 'bus_plate', b.plate,
    'driver_name', (select p.full_name from drivers d join profiles p on p.id = d.profile_id
                    where d.id = b.driver_id),
    'route_name', r.name,
    'pickup_stop', (select rs.name from route_stops rs where rs.id = st.pickup_stop_id),
    'dropoff_stop', (select rs.name from route_stops rs where rs.id = st.dropoff_stop_id)
  ) into v_result
  from student_transport st
  left join buses b on b.id = st.bus_id
  left join transport_routes r on r.id = st.route_id
  where st.student_id = p_student_id;

  return v_result; -- null when the student has no transport assignment
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
    'bus_code', v_bus.code,
    'bus_plate', v_bus.plate,
    'bus_capacity', v_bus.capacity
  );
end;
$$;

revoke all on function fn_driver_context() from public;
grant execute on function fn_driver_context() to authenticated;

-- 9.8 fn_start_trip — the assigned driver starts a trip; any still-active trip
--     on the same bus is auto-completed first.
create or replace function fn_start_trip(p_route_id uuid default null, p_direction text default 'pickup')
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_ctx jsonb;
  v_bus_id uuid;
  v_driver_id uuid;
  v_school_id uuid;
  v_id uuid;
begin
  v_ctx := fn_driver_context();
  if v_ctx is null then raise exception 'NOT_A_DRIVER'; end if;

  v_bus_id := (v_ctx->>'bus_id')::uuid;
  v_driver_id := (v_ctx->>'driver_id')::uuid;
  v_school_id := (v_ctx->>'school_id')::uuid;
  if v_bus_id is null then raise exception 'NO_BUS_ASSIGNED'; end if;
  if coalesce(p_direction, 'pickup') not in ('pickup', 'dropoff') then
    raise exception 'INVALID_DIRECTION';
  end if;

  update trips set status = 'completed', ended_at = now()
  where bus_id = v_bus_id and status = 'active';

  insert into trips (school_id, bus_id, route_id, driver_id, direction, status)
  values (v_school_id, v_bus_id, p_route_id, v_driver_id, coalesce(p_direction, 'pickup'), 'active')
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'START_TRIP', 'trips', v_id,
    null, jsonb_build_object('bus_id', v_bus_id, 'direction', p_direction));
  return v_id;
end;
$$;

revoke all on function fn_start_trip(uuid, text) from public;
grant execute on function fn_start_trip(uuid, text) to authenticated;

-- 9.9 fn_end_trip — driver of the trip or school staff.
create or replace function fn_end_trip(p_trip_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_trip trips%rowtype;
  v_ctx jsonb;
begin
  select * into v_trip from trips where id = p_trip_id;
  if v_trip.id is null then raise exception 'INVALID_TRIP'; end if;

  v_ctx := fn_driver_context();
  if not (fn_is_school_staff(v_trip.school_id)
          or (v_ctx is not null and (v_ctx->>'driver_id')::uuid = v_trip.driver_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  update trips set status = 'completed', ended_at = now() where id = p_trip_id;

  perform fn_safe_audit(v_trip.school_id, 'END_TRIP', 'trips', p_trip_id, null, null);
end;
$$;

revoke all on function fn_end_trip(uuid) from public;
grant execute on function fn_end_trip(uuid) to authenticated;

-- 9.10 fn_record_trip_event — board/alight a student on an active trip.
create or replace function fn_record_trip_event(p_trip_id uuid, p_student_id uuid, p_event_type text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_trip trips%rowtype;
  v_ctx jsonb;
begin
  select * into v_trip from trips where id = p_trip_id;
  if v_trip.id is null then raise exception 'INVALID_TRIP'; end if;
  if v_trip.status <> 'active' then raise exception 'TRIP_NOT_ACTIVE'; end if;
  if coalesce(p_event_type, '') not in ('board', 'alight') then
    raise exception 'INVALID_EVENT_TYPE';
  end if;

  v_ctx := fn_driver_context();
  if not (fn_is_school_staff(v_trip.school_id)
          or (v_ctx is not null and (v_ctx->>'driver_id')::uuid = v_trip.driver_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  -- The student must be assigned to this trip's bus.
  if not exists (select 1 from student_transport st
                 where st.student_id = p_student_id and st.bus_id = v_trip.bus_id) then
    raise exception 'STUDENT_NOT_ON_BUS';
  end if;

  insert into trip_events (trip_id, student_id, event_type, recorded_by)
  values (p_trip_id, p_student_id, p_event_type, auth.uid())
  on conflict (trip_id, student_id, event_type) do nothing;
end;
$$;

revoke all on function fn_record_trip_event(uuid, uuid, text) from public;
grant execute on function fn_record_trip_event(uuid, uuid, text) to authenticated;

-- 9.11 fn_get_active_trip — the calling driver's active trip with its events.
create or replace function fn_get_active_trip()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_ctx jsonb;
  v_trip trips%rowtype;
begin
  v_ctx := fn_driver_context();
  if v_ctx is null then return null; end if;

  select * into v_trip from trips
  where driver_id = (v_ctx->>'driver_id')::uuid and status = 'active'
  order by started_at desc limit 1;
  if v_trip.id is null then return null; end if;

  return jsonb_build_object(
    'trip_id', v_trip.id,
    'direction', v_trip.direction,
    'started_at', v_trip.started_at,
    'route_id', v_trip.route_id,
    'route_name', (select r.name from transport_routes r where r.id = v_trip.route_id),
    'bus_code', v_ctx->>'bus_code',
    'events', coalesce((select jsonb_agg(jsonb_build_object(
                 'student_id', te.student_id, 'event_type', te.event_type, 'at', te.created_at))
               from trip_events te where te.trip_id = v_trip.id), '[]'::jsonb)
  );
end;
$$;

revoke all on function fn_get_active_trip() from public;
grant execute on function fn_get_active_trip() to authenticated;

-- 9.12 fn_list_bus_students — students assigned to a bus with today's events.
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
  select st.student_id, s.full_name, s.student_number,
         (select rs.name from route_stops rs where rs.id = st.pickup_stop_id),
         (select rs.name from route_stops rs where rs.id = st.dropoff_stop_id),
         (select te.created_at from trip_events te
          where te.trip_id = p_trip_id and te.student_id = st.student_id and te.event_type = 'board'),
         (select te.created_at from trip_events te
          where te.trip_id = p_trip_id and te.student_id = st.student_id and te.event_type = 'alight')
  from student_transport st
  join students s on s.id = st.student_id and s.deleted_at is null
  where st.bus_id = p_bus_id
  order by s.full_name;
end;
$$;

revoke all on function fn_list_bus_students(uuid, uuid) from public;
grant execute on function fn_list_bus_students(uuid, uuid) to authenticated;

-- 9.13 fn_my_trips — the calling driver's recent trips.
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
  select t.id, t.trip_date, t.direction, t.status,
         (select r.name from transport_routes r where r.id = t.route_id),
         t.started_at, t.ended_at,
         (select count(*) from trip_events te where te.trip_id = t.id)
  from trips t
  where t.driver_id = (v_ctx->>'driver_id')::uuid
  order by t.started_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_my_trips(int) from public;
grant execute on function fn_my_trips(int) to authenticated;

-- ============================================================================
-- SECTION 10 — FINANCE (fee payments + expenses)
-- ============================================================================

create table if not exists fee_payments (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  student_id uuid not null references students(id) on delete cascade,
  fee_type text not null,
  amount_due numeric not null default 0,
  amount_paid numeric not null default 0,
  payment_date date not null default current_date,
  method text,
  receipt_no text,
  note text,
  recorded_by uuid references profiles(id),
  created_at timestamptz not null default now()
);

create table if not exists expenses (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  category text not null,
  amount numeric not null,
  expense_date date not null default current_date,
  description text,
  recorded_by uuid references profiles(id),
  created_at timestamptz not null default now()
);

create index if not exists ix_payments_school on fee_payments (school_id, payment_date desc);
create index if not exists ix_expenses_school on expenses (school_id, expense_date desc);

alter table fee_payments enable row level security;
alter table expenses enable row level security;

-- 10.1 fn_record_payment — finance.manage or staff.
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
begin
  select school_id into v_school_id from students where id = p_student_id;
  if v_school_id is null then raise exception 'INVALID_STUDENT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('finance.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_fee_type is null or trim(p_fee_type) = '' then raise exception 'FEE_TYPE_REQUIRED'; end if;
  if coalesce(p_amount_paid, 0) < 0 or coalesce(p_amount_due, 0) < 0 then
    raise exception 'INVALID_AMOUNT';
  end if;

  insert into fee_payments (school_id, student_id, fee_type, amount_due, amount_paid,
                            payment_date, method, receipt_no, note, recorded_by)
  values (v_school_id, p_student_id, trim(p_fee_type),
          coalesce(p_amount_due, 0), coalesce(p_amount_paid, 0),
          coalesce(p_payment_date, current_date),
          nullif(trim(coalesce(p_method, '')), ''),
          ('RC-' || to_char(now(), 'YYYYMMDD-HH24MISS')),
          nullif(trim(coalesce(p_note, '')), ''),
          auth.uid())
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'RECORD_PAYMENT', 'fee_payments', v_id,
    null, jsonb_build_object('student_id', p_student_id, 'amount_paid', p_amount_paid));
  return v_id;
end;
$$;

revoke all on function fn_record_payment(uuid, text, numeric, numeric, date, text, text) from public;
grant execute on function fn_record_payment(uuid, text, numeric, numeric, date, text, text) to authenticated;

-- 10.2 fn_list_payments — staff/finance.view; a parent may read their own
--      child's payments via fn_child_payments below.
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
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id)
          or fn_has_permission('finance.view', v_school_id)
          or (p_student_id is not null and fn_is_parent_of(p_student_id))) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select fp.id, fp.student_id, st.full_name, fp.fee_type, fp.amount_due, fp.amount_paid,
         fp.payment_date, fp.method, fp.receipt_no, fp.note
  from fee_payments fp
  join students st on st.id = fp.student_id
  where fp.school_id = v_school_id
    and (p_student_id is null or fp.student_id = p_student_id)
  order by fp.payment_date desc, fp.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_list_payments(uuid, int) from public;
grant execute on function fn_list_payments(uuid, int) to authenticated;

-- 10.3 fn_record_expense / fn_list_expenses.
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
  v_id uuid;
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('finance.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_category is null or trim(p_category) = '' then raise exception 'EXPENSE_CATEGORY_REQUIRED'; end if;
  if p_amount is null or p_amount <= 0 then raise exception 'INVALID_AMOUNT'; end if;

  insert into expenses (school_id, category, amount, expense_date, description, recorded_by)
  values (v_school_id, trim(p_category), p_amount, coalesce(p_expense_date, current_date),
          nullif(trim(coalesce(p_description, '')), ''), auth.uid())
  returning id into v_id;

  perform fn_safe_audit(v_school_id, 'RECORD_EXPENSE', 'expenses', v_id,
    null, jsonb_build_object('category', trim(p_category), 'amount', p_amount));
  return v_id;
end;
$$;

revoke all on function fn_record_expense(text, numeric, date, text) from public;
grant execute on function fn_record_expense(text, numeric, date, text) to authenticated;

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
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('finance.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select e.id, e.category, e.amount, e.expense_date, e.description,
         (select p.full_name from profiles p where p.id = e.recorded_by)
  from expenses e
  where e.school_id = v_school_id
  order by e.expense_date desc, e.created_at desc
  limit p_limit;
end;
$$;

revoke all on function fn_list_expenses(int) from public;
grant execute on function fn_list_expenses(int) to authenticated;

-- 10.4 fn_finance_summary — totals for a date range (defaults: this month).
create or replace function fn_finance_summary(p_from date default null, p_to date default null)
returns table(total_due numeric, total_paid numeric, total_expenses numeric, net numeric)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_from date := coalesce(p_from, date_trunc('month', current_date)::date);
  v_to date := coalesce(p_to, current_date);
begin
  v_school_id := fn_my_primary_school();
  if v_school_id is null then raise exception 'NO_SCHOOL_CONTEXT'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('finance.view', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;

  return query
  select
    coalesce((select sum(amount_due) from fee_payments
              where school_id = v_school_id and payment_date between v_from and v_to), 0),
    coalesce((select sum(amount_paid) from fee_payments
              where school_id = v_school_id and payment_date between v_from and v_to), 0),
    coalesce((select sum(amount) from expenses
              where school_id = v_school_id and expense_date between v_from and v_to), 0),
    coalesce((select sum(amount_paid) from fee_payments
              where school_id = v_school_id and payment_date between v_from and v_to), 0)
    - coalesce((select sum(amount) from expenses
                where school_id = v_school_id and expense_date between v_from and v_to), 0);
end;
$$;

revoke all on function fn_finance_summary(date, date) from public;
grant execute on function fn_finance_summary(date, date) to authenticated;

-- ============================================================================
-- SECTION 11 — CLASS SCHEDULE
-- ============================================================================

create table if not exists class_schedule (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  class_id uuid not null references classes(id) on delete cascade,
  weekday smallint not null check (weekday between 0 and 6), -- 0 = Sunday
  period smallint not null,
  subject_id uuid references subjects(id) on delete set null,
  subject_label text,
  teacher_id uuid references teachers(id) on delete set null,
  unique (class_id, weekday, period)
);

alter table class_schedule enable row level security;

-- 11.1 fn_set_class_schedule — replace one weekday's periods for a class.
--      p_entries: [{"weekday":0,"period":1,"subject_id":uuid?,"subject_label":text?,"teacher_id":uuid?}]
create or replace function fn_set_class_schedule(p_class_id uuid, p_entries jsonb)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
  v_entry jsonb;
  v_count integer := 0;
begin
  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then raise exception 'INVALID_CLASS'; end if;
  if not (fn_is_school_staff(v_school_id) or fn_has_permission('schedule.manage', v_school_id)) then
    raise exception 'PERMISSION_DENIED';
  end if;
  if p_entries is null or jsonb_typeof(p_entries) <> 'array' then
    raise exception 'INVALID_ROWS';
  end if;

  for v_entry in select * from jsonb_array_elements(p_entries)
  loop
    if (v_entry->>'weekday')::smallint not between 0 and 6
       or (v_entry->>'period')::smallint is null then
      continue;
    end if;
    insert into class_schedule (school_id, class_id, weekday, period, subject_id, subject_label, teacher_id)
    values (
      v_school_id, p_class_id,
      (v_entry->>'weekday')::smallint, (v_entry->>'period')::smallint,
      nullif(v_entry->>'subject_id', '')::uuid,
      nullif(trim(coalesce(v_entry->>'subject_label', '')), ''),
      nullif(v_entry->>'teacher_id', '')::uuid
    )
    on conflict (class_id, weekday, period) do update
      set subject_id = excluded.subject_id,
          subject_label = excluded.subject_label,
          teacher_id = excluded.teacher_id;
    v_count := v_count + 1;
  end loop;
  return v_count;
end;
$$;

revoke all on function fn_set_class_schedule(uuid, jsonb) from public;
grant execute on function fn_set_class_schedule(uuid, jsonb) to authenticated;

-- 11.2 fn_get_class_schedule — members of the school.
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
  select school_id into v_school_id from classes where id = p_class_id;
  if v_school_id is null then raise exception 'INVALID_CLASS'; end if;
  if not fn_is_school_member(v_school_id) then raise exception 'PERMISSION_DENIED'; end if;

  return query
  select cs.weekday, cs.period,
         coalesce(su.name, cs.subject_label),
         (select p.full_name from teachers t join profiles p on p.id = t.profile_id
          where t.id = cs.teacher_id)
  from class_schedule cs
  left join subjects su on su.id = cs.subject_id
  where cs.class_id = p_class_id
  order by cs.weekday, cs.period;
end;
$$;

revoke all on function fn_get_class_schedule(uuid) from public;
grant execute on function fn_get_class_schedule(uuid) to authenticated;

-- 11.3 fn_teacher_classes — classes assigned to the calling teacher.
create or replace function fn_teacher_classes()
returns table(class_id uuid, class_name text, level text, year_name text, student_count bigint)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_teacher_id uuid;
begin
  select t.id into v_teacher_id from teachers t
  where t.profile_id = auth.uid() and t.deleted_at is null
  limit 1;
  if v_teacher_id is null then
    return;
  end if;

  return query
  select c.id, c.name, c.level, ay.name,
         (select count(*) from student_enrollments se
          where se.class_id = c.id and se.status = 'ACTIVE')
  from classes c
  join academic_years ay on ay.id = c.academic_year_id
  where c.teacher_id = v_teacher_id
    and not c.is_disabled
  order by ay.is_current desc, c.name;
end;
$$;

revoke all on function fn_teacher_classes() from public;
grant execute on function fn_teacher_classes() to authenticated;

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
    'year_name', (select ay.name from student_enrollments se
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

  return query
  select fp.fee_type, fp.amount_due, fp.amount_paid, fp.payment_date, fp.receipt_no
  from fee_payments fp
  where fp.student_id = p_student_id
  order by fp.payment_date desc
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
    'payments_month', coalesce((select sum(amount_paid) from fee_payments
                        where school_id = v_school_id
                          and payment_date >= date_trunc('month', current_date)::date), 0),
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
-- END OF PHASE 12 COMPLETE PLATFORM MIGRATION
-- ============================================================================
