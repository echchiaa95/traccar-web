-- ============================================================================
-- supabase/migrations/phase3_4_remembered_device.sql
-- PHASE 3.4 — "remember this device" support.
-- The ONLY server-side change needed: fn_verify_login now also returns the
-- account's user_number on success, so the Edge Function can hand it back
-- to the frontend to cache locally (modules/device.js). Every check inside
-- fn_verify_login (identify -> is_disabled -> pin match -> lock -> rate
-- limit) is UNCHANGED — this migration only widens its OUTPUT.
--
-- Remembered-device logins are NOT a new auth mode: they simply replay
-- method:'manual' with the cached user_number (see modules/auth.js +
-- index.html), so no new RPC, no new Edge Function branch, and no new
-- rate-limiting logic are required. Run this AFTER phase3_3.
-- ============================================================================

-- CREATE OR REPLACE cannot change a function's OUT columns, so the function
-- must be dropped first. Same body otherwise; the only diffs are the
-- `returns table(...)` signature and the two lines assigning user_number.
drop function if exists fn_verify_login(text, text, text, text);

create or replace function fn_verify_login(p_method text, p_identifier text, p_pin text, p_ip text)
returns table(profile_id uuid, user_number text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_recent_ip_count int;
  v_recent_id_count int;
  v_profile_id uuid;
  v_user_number text;
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

  select count(*) into v_recent_ip_count from pin_login_attempts
  where ip_address = p_ip and attempted_at > now() - interval '15 minutes';
  if v_recent_ip_count >= 20 then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  select count(*) into v_recent_id_count from pin_login_attempts
  where identifier_key = v_identifier_key and attempted_at > now() - interval '15 minutes';
  if v_recent_id_count >= 10 then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  if p_method = 'qr' then
    begin
      select lqt.profile_id into v_profile_id
      from login_qr_tokens lqt
      where lqt.token = p_identifier::uuid and lqt.status = 'ACTIVE';
    exception when invalid_text_representation then
      v_profile_id := null;
    end;
  else
    select p.id into v_profile_id from profiles p where p.user_number = p_identifier;
  end if;

  if v_profile_id is null then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

  select p.is_disabled, p.user_number into v_is_disabled, v_user_number
  from profiles p where p.id = v_profile_id;

  if v_is_disabled then
    insert into pin_login_attempts(ip_address, succeeded, identifier_key) values (p_ip, false, v_identifier_key);
    return;
  end if;

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
  user_number := v_user_number; -- NEW: may be null if this account has none yet
  return next;
end;
$$;

revoke all on function fn_verify_login(text, text, text, text) from public;
grant execute on function fn_verify_login(text, text, text, text) to service_role;

-- ============================================================================
-- END OF PHASE 3.4 MIGRATION
-- ============================================================================
