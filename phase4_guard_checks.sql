-- ============================================================================
-- supabase/migrations/phase4_guard_checks.sql
-- PHASE 4 — Guard console control history.
-- Adds ONE new table. Nothing from phase2_schema.sql or the phase3_* auth
-- migrations is modified, dropped, or renamed. Run this AFTER phase3_4.
--
-- Why a plain table + RLS instead of a new RPC: this is an append-only
-- activity log for a routine, non-financial, non-identity action (a guard
-- looking up a student's status at the gate). It doesn't need the
-- SECURITY DEFINER + cross-table validation chain that bus scans or
-- attendance require (Architecture v1.1 §12) — a straightforward
-- `with check` on role + own profile_id is sufficient and keeps this
-- addition minimal, per Phase 4's instruction to avoid unnecessary
-- backend rework.
-- ============================================================================

create table guard_checks (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references schools(id) on delete cascade,
  student_id uuid references students(id) on delete set null, -- null when the token/search matched no one
  checked_by uuid not null references profiles(id),
  method text not null check (method in ('qr','manual')),
  result text not null check (result in ('AUTHORIZED','UNAUTHORIZED','ABSENT_INACTIVE','UNKNOWN_ERROR')),
  created_at timestamptz not null default now()
);
create index ix_guard_checks_school_time on guard_checks(school_id, created_at desc);
create index ix_guard_checks_guard_time on guard_checks(checked_by, created_at desc);

alter table guard_checks enable row level security;

-- Read: staff (admin/guard/director) within the same school.
create policy p_guard_checks_staff_read on guard_checks for select using (
  fn_has_role(school_id, array['admin','guard','director']::app_role[])
);

-- Write: guard/admin only, and only ever logging themselves as checked_by —
-- a client cannot log a check "as" another guard.
create policy p_guard_checks_insert on guard_checks for insert with check (
  checked_by = auth.uid() and fn_is_admin_or_guard(school_id)
);
-- No UPDATE/DELETE policy: append-only, same philosophy as audit_logs.

-- ============================================================================
-- END OF PHASE 4 MIGRATION
-- ============================================================================
