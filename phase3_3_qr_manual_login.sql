-- ============================================================================
-- supabase/migrations/phase3_3_qr_manual_login.sql
-- PHASE 3.3 — two-factor login: (QR token | user_number) + PIN.
-- Layers on top of phase2_schema.sql + phase3_2_pin_login.sql. Nothing from
-- either is removed except fn_verify_staff_pin, which this migration
-- explicitly supersedes (the PIN is no longer looked up by scanning every
-- hash — it's now looked up for one specific, already-identified account).
-- Run this AFTER phase3_2_pin_login.sql.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. user_number — the manual-login identifier. Lives on `profiles` since
--    it identifies the ACCOUNT, one per person, same lifetime as the profile.
-- ----------------------------------------------------------------------------
alter table profiles add column user_number text;
create unique index ux_profiles_user_number on profiles(user_number) where user_number is not null;
-- Nullable + partial unique index (not NOT NULL) so this migration doesn't
-- break existing profiles that haven't been assigned a number yet; assign
-- one before enabling manual login for that account.

-- ----------------------------------------------------------------------------
-- 2. login_qr_tokens — mirrors the student_badges design deliberately
--    (Architecture v1.1 §7): opaque random token, exactly one ACTIVE per
--    profile, full history kept, reissue instead of edit-in-place.
-- ----------------------------------------------------------------------------
create table login_qr_tokens (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  token uuid not null default gen_random_uuid(),
  status text not null default 'ACTIVE' check (status in ('ACTIVE','REVOKED','REPLACED')),
  replaced_by uuid references login_qr_tokens(id),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique (token)
);
create index ix_login_qr_profile on login_qr_tokens(profile_id);
create unique index ux_login_qr_active_per_profile
  on login_qr_tokens(profile_id) where status = 'ACTIVE';

alter table login_qr_tokens enable row level security;
-- Owner may see that a token exists (not its value is not hidden by RLS —
-- token is already an opaque unguessable UUID, no extra secrecy needed
-- for the row itself) so they can tell whether they have an active QR.
create policy p_login_qr_self on login_qr_tokens for select using (profile_id = auth.uid());
create policy p_login_qr_staff on login_qr_tokens for select using (
  exists (
    select 1 from user_roles ur where ur.profile_id = auth.uid()
      and ur.role in ('admin','guard')
      and exists (select 1 from user_roles ur2 where ur2.profile_id = login_qr_tokens.profile_id and ur2.school_id = ur.school_id)
  )
);
-- No client-facing INSERT/UPDATE/DELETE: issuing/revoking a login QR is an
-- administrative action, done only via fn_issue_login_qr/fn_revoke_login_qr
-- (service_role only, see below) — never directly by the client.

-- ----------------------------------------------------------------------------
-- 3. pin_login_attempts gets an identifier_key column so we can throttle
--    per-identifier as well as per-IP (doc requirement: "limitation
--    raisonnable par compte ciblé après identification", without allowing
--    permanent lockout of a victim by an attacker who only knows their
--    user_number/QR value).
-- ----------------------------------------------------------------------------
alter table pin_login_attempts add column identifier_key text;
create index ix_pin_attempts_identifier_time on pin_login_attempts(identifier_key, attempted_at desc);

-- ----------------------------------------------------------------------------
-- 4. Weak-PIN denylist, enforced at PROVISIONING time (fn_set_user_pin),
--    never at login time (checking against a denylist during login would
--    itself leak information about which PINs are "interesting").
-- ----------------------------------------------------------------------------
create or replace function fn_is_weak_pin(p_pin text)
returns boolean
language sql
immutable
as $$
  select
    p_pin in ('0000','1111','2222','3333','4444','5555','6666','7777','8888','9999',
              '1234','2345','3456','4567','5678','6789','9876','8765','7654','6543',
              '5432','4321','0123','1212','2121','1122')
    or p_pin ~ '^(\d)\1{3}$';           -- any 4 repeated digits (covers the list above too, kept explicit for clarity)
$$;

-- ----------------------------------------------------------------------------
-- 5. fn_set_user_pin — the provisioning half (assign/reset a PIN).
--    service_role only; a future admin tool / Edge Function calls this.
--    Rejects weak PINs here, where it's safe to give a specific error.
-- ----------------------------------------------------------------------------
create or replace function fn_set_user_pin(p_profile_id uuid, p_pin text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_pin !~ '^[0-9]{4}$' then
    raise exception 'INVALID_PIN_FORMAT';
  end if;
  if fn_is_weak_pin(p_pin) then
    raise exception 'PIN_TOO_WEAK';
  end if;

  insert into staff_pins(profile_id, pin_hash, updated_at)
  values (p_profile_id, crypt(p_pin, gen_salt('bf')), now())
  on conflict (profile_id) do update
    set pin_hash = excluded.pin_hash, locked_until = null, updated_at = now();
end;
$$;
revoke all on function fn_set_user_pin(uuid, text) from public;
grant execute on function fn_set_user_pin(uuid, text) to service_role;

-- ----------------------------------------------------------------------------
-- 6. fn_issue_login_qr / fn_revoke_login_qr — minimal QR lifecycle,
--    mirroring fn_issue_badge/fn_reissue_badge. service_role only.
-- ----------------------------------------------------------------------------
create or replace function fn_issue_login_qr(p_profile_id uuid)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old_id uuid;
  v_new_id uuid;
begin
  select id into v_old_id from login_qr_tokens
  where profile_id = p_profile_id and status = 'ACTIVE' for update;

  -- demote old FIRST (same ordering fix as fn_reissue_badge — the partial
  -- unique index would reject a second ACTIVE row otherwise)
  if v_old_id is not null then
    update login_qr_tokens set status = 'REPLACED' where id = v_old_id;
  end if;

  insert into login_qr_tokens(profile_id) values (p_profile_id)
  returning id into v_new_id;

  if v_old_id is not null then
    update login_qr_tokens set replaced_by = v_new_id where id = v_old_id;
  end if;

  return v_new_id;
end;
$$;
revoke all on function fn_issue_login_qr(uuid) from public;
grant execute on function fn_issue_login_qr(uuid) to service_role;

create or replace function fn_revoke_login_qr(p_profile_id uuid)
returns void
language sql
security definer
set search_path = public
as $$
  update login_qr_tokens set status = 'REVOKED', revoked_at = now()
  where profile_id = p_profile_id and status = 'ACTIVE';
$$;
revoke all on function fn_revoke_login_qr(uuid) from public;
grant execute on function fn_revoke_login_qr(uuid) to service_role;

-- ----------------------------------------------------------------------------
-- 7. fn_verify_login — replaces fn_verify_staff_pin. Identifies the account
--    via QR token or user_number FIRST, then checks the PIN for that one
--    account only (no more full-table crypt() scan). Same IP throttle as
--    before, PLUS a per-identifier throttle. Same account is_disabled
--    check moved here (defense in depth — blocked before a session is even
--    minted, not just afterward in getAuthenticatedContext()).
-- ----------------------------------------------------------------------------
drop function if exists fn_verify_staff_pin(text, text); -- superseded by this function

create or replace function fn_verify_login(p_method text, p_identifier text, p_pin text, p_ip text)
returns table(profile_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_recent_ip_count int;
  v_recent_id_count int;
  v_profile_id uuid;
  v_pin_hash text;
  v_locked_until timestamptz;
  v_is_disabled boolean;
  v_identifier_key text;
begin
  if p_method not in ('qr','manual') then
    return;
  end if;
  if p_pin !~ '^[0-9]{4}$' then
    return;
  end if;
  if p_identifier is null or length(p_identifier) = 0 or length(p_identifier) > 128 then
    return;
  end if;

  v_identifier_key := p_method || ':' || p_identifier;

  -- IP throttle (unchanged from Phase 3.2: 20 / 15 min)
  select count(*) into v_recent_ip_count from pin_login_attempts
  where ip_address = p_ip and attempted_at > now() - interval '15 minutes';
  if v_recent_ip_count >= 20 then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  -- Per-identifier throttle: generous enough not to be a nuisance for the
  -- real owner, tight enough to blunt a targeted guessing run — and it
  -- self-resets (rolling window), so an attacker can only cause temporary
  -- generic failures, never a lasting lockout of someone else's account.
  select count(*) into v_recent_id_count from pin_login_attempts
  where identifier_key = v_identifier_key and attempted_at > now() - interval '15 minutes';
  if v_recent_id_count >= 10 then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  -- Step 1: identify the account (QR token or user_number) — NOT the PIN yet.
  if p_method = 'qr' then
    begin
      select lqt.profile_id into v_profile_id
      from login_qr_tokens lqt
      where lqt.token = p_identifier::uuid and lqt.status = 'ACTIVE';
    exception when invalid_text_representation then
      v_profile_id := null; -- malformed UUID input, treat as unknown
    end;
  else
    select p.id into v_profile_id from profiles p where p.user_number = p_identifier;
  end if;

  if v_profile_id is null then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return; -- unknown QR/user_number: SAME generic failure as wrong PIN
  end if;

  select is_disabled into v_is_disabled from profiles where id = v_profile_id;
  if v_is_disabled then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  -- Step 2: verify the PIN for THIS account only.
  select sp.pin_hash, sp.locked_until into v_pin_hash, v_locked_until
  from staff_pins sp where sp.profile_id = v_profile_id;

  if v_pin_hash is null or v_pin_hash <> crypt(p_pin, v_pin_hash) then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  if v_locked_until is not null and v_locked_until > now() then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, true, v_identifier_key);
  profile_id := v_profile_id;
  return next;
end;
$$;
revoke all on function fn_verify_login(text, text, text, text) from public;
grant execute on function fn_verify_login(text, text, text, text) to service_role;

-- ============================================================================
-- END OF PHASE 3.3 MIGRATION
-- ============================================================================
