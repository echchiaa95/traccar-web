-- ============================================================================
-- supabase/migrations/phase3_2_pin_login.sql
-- PHASE 3.2 — PIN-based login support.
-- Adds ONLY what's new: staff_pins, pin_login_attempts, fn_verify_staff_pin.
-- Nothing from phase2_schema.sql / architecture-v1.1 is modified or removed.
-- Run this AFTER phase2_schema.sql.
-- ============================================================================

create extension if not exists pgcrypto; -- already present from Phase 2, safe to repeat

-- ----------------------------------------------------------------------------
-- staff_pins: one bcrypt-hashed PIN per profile. The raw PIN is NEVER
-- stored — only crypt()'s bcrypt output. profile_id is the PRIMARY KEY
-- (not a separate id), so a profile can have at most one PIN row.
-- ----------------------------------------------------------------------------
create table staff_pins (
  profile_id uuid primary key references profiles(id) on delete cascade,
  pin_hash text not null,
  locked_until timestamptz,          -- reserved for future admin-triggered lock; see note below
  updated_at timestamptz not null default now()
);

alter table staff_pins enable row level security;
-- INTENTIONALLY NO POLICIES: staff_pins is readable/writable ONLY by the
-- service role (used inside the Edge Function and fn_verify_staff_pin,
-- both of which bypass RLS). No client role (anon/authenticated) can ever
-- SELECT a pin_hash — RLS defaults to deny-all with zero policies.

-- ----------------------------------------------------------------------------
-- pin_login_attempts: IP-level rate limiting log. This is the primary
-- brute-force defense — since the PIN alone identifies the user (no
-- separate username step), a wrong guess can't be attributed to a specific
-- profile, so per-profile lockout isn't reliable here; IP throttling is.
-- ----------------------------------------------------------------------------
create table pin_login_attempts (
  id uuid primary key default gen_random_uuid(),
  ip_address text not null,
  succeeded boolean not null default false,
  attempted_at timestamptz not null default now()
);
create index ix_pin_attempts_ip_time on pin_login_attempts(ip_address, attempted_at desc);
alter table pin_login_attempts enable row level security;
-- INTENTIONALLY NO POLICIES: written only by fn_verify_staff_pin (service role).

-- ----------------------------------------------------------------------------
-- fn_verify_staff_pin: the ONLY place a PIN is ever compared.
--  - Re-validates the 4-digit format (defense in depth; Edge Function
--    already checked it).
--  - Throttles by IP: max 20 attempts per rolling 15 minutes.
--  - Matches the PIN against every staff_pins row using pgcrypto's crypt(),
--    which recomputes the bcrypt hash with the salt embedded in the stored
--    hash and compares — this is a full-table scan, which is fine for a
--    staff-sized table (tens to low hundreds of rows), not for large ones.
--  - Never returns a hash, never returns *why* it failed — just a
--    profile_id row on success, or an empty result set on any failure.
--  - EXECUTE is granted to service_role ONLY (see grants below) — an
--    authenticated or anon client can never call this directly, even
--    though it's SECURITY DEFINER.
-- ----------------------------------------------------------------------------
create or replace function fn_verify_staff_pin(p_pin text, p_ip text)
returns table(profile_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_recent_ip_count int;
  v_profile_id uuid;
  v_locked_until timestamptz;
begin
  if p_pin !~ '^[0-9]{4}$' then
    insert into pin_login_attempts(ip_address, succeeded) values (coalesce(p_ip, 'unknown'), false);
    return; -- empty result set
  end if;

  select count(*) into v_recent_ip_count
  from pin_login_attempts
  where ip_address = p_ip and attempted_at > now() - interval '15 minutes';

  if v_recent_ip_count >= 20 then
    insert into pin_login_attempts(ip_address, succeeded) values (p_ip, false);
    return;
  end if;

  select sp.profile_id, sp.locked_until into v_profile_id, v_locked_until
  from staff_pins sp
  where sp.pin_hash = crypt(p_pin, sp.pin_hash)
  limit 1;

  insert into pin_login_attempts(ip_address, succeeded) values (p_ip, v_profile_id is not null);

  if v_profile_id is null then
    return;
  end if;

  if v_locked_until is not null and v_locked_until > now() then
    return; -- matched a PIN, but that account is administratively locked
  end if;

  profile_id := v_profile_id;
  return next;
end;
$$;

-- Lock this function down: only the service role (Edge Function) may call
-- it. Neither anon nor authenticated get EXECUTE, even though it's
-- SECURITY DEFINER — defense in depth against calling it straight from a
-- browser with supabase.rpc(), which would bypass the Edge Function
-- entirely (and its CORS/origin restrictions) if this weren't revoked.
revoke all on function fn_verify_staff_pin(text, text) from public;
grant execute on function fn_verify_staff_pin(text, text) to service_role;

-- ----------------------------------------------------------------------------
-- Helper for provisioning: hash a PIN the same way fn_verify_staff_pin
-- expects, for use by an admin tool / Edge Function when ASSIGNING a PIN
-- to staff (out of scope for this phase's login flow, but needed the
-- moment someone wants to set/reset a PIN — included so that path uses the
-- exact same hashing scheme rather than drifting).
-- ----------------------------------------------------------------------------
create or replace function fn_hash_pin(p_pin text)
returns text
language sql
immutable
as $$
  select crypt(p_pin, gen_salt('bf'));
$$;
revoke all on function fn_hash_pin(text) from public;
grant execute on function fn_hash_pin(text) to service_role;

-- ============================================================================
-- END OF PHASE 3.2 MIGRATION
-- ============================================================================
