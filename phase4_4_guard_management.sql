-- ============================================================================
-- supabase/migrations/phase4_4_guard_management.sql
-- PHASE 4.4 — the ONE new function needed for Admin/Guard management.
--
-- AUDIT FINDING: profiles has no UPDATE policy usable by an admin to
-- disable ANOTHER user's account (p_profiles_self_update only allows
-- `id = auth.uid()`). Enabling/disabling a Guard therefore needs a
-- SECURITY DEFINER function — this is the only genuine gap; everything
-- else (guard creation, permission grant/revoke, listing) reuses existing
-- functions/tables/RLS unchanged.
--
-- SAFETY: purely additive (one new function). No table created, no
-- existing table/RLS/function modified. Nothing in Authentication touched.
-- ============================================================================

create or replace function fn_set_guard_status(p_profile_id uuid, p_is_disabled boolean)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_school_id uuid;
begin
  -- The one school where BOTH hold: the CALLER is admin/director there,
  -- AND the TARGET holds the guard role there. This is the safe way to
  -- resolve "which school does this admin action apply to" — an admin in
  -- School A can never affect a guard who is only a guard in School B,
  -- because no single school_id can satisfy both halves of the join.
  select ur_target.school_id into v_school_id
  from user_roles ur_target
  join user_roles ur_admin
    on ur_admin.school_id = ur_target.school_id
   and ur_admin.profile_id = auth.uid()
   and ur_admin.role in ('admin','director')
  where ur_target.profile_id = p_profile_id
    and ur_target.role = 'guard'
  limit 1;

  if v_school_id is null then
    raise exception 'PERMISSION_DENIED_OR_NOT_A_GUARD_IN_YOUR_SCHOOL';
  end if;

  update profiles set is_disabled = p_is_disabled where id = p_profile_id;

  perform fn_write_audit(
    v_school_id,
    case when p_is_disabled then 'GUARD_DISABLED' else 'GUARD_ENABLED' end,
    'profiles', p_profile_id, null,
    jsonb_build_object('is_disabled', p_is_disabled)
  );
end;
$$;
revoke all on function fn_set_guard_status(uuid, boolean) from public;
grant execute on function fn_set_guard_status(uuid, boolean) to authenticated;

-- ============================================================================
-- END OF PHASE 4.4 MIGRATION
-- ============================================================================
