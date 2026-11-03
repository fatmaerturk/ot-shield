-- User-management hardening migration (2026-11-03)
--
-- The project runs with spring.jpa.hibernate.ddl-auto=none (schema is fixed and
-- migrated via pg_dump/pg_restore), so entity changes do NOT auto-apply. Run this
-- against each database (dev + cloud) when deploying the user-management hardening:
--
--   docker compose exec -T postgres psql -U otshield -d otshield_db -f - < this.sql
--
-- Idempotent: safe to run more than once.

-- 1. Failed-login lockout support (User.lockedUntil). NULL = not locked.
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;

-- 2. Give the demo analyst/operator accounts their real canonical roles. They were
--    both stored as the legacy ROLE_USER, so RBAC could not tell them apart. The
--    admin accounts (is_admin = true) are left untouched.
UPDATE users SET role = 'ROLE_ANALYST'
  WHERE lower(email) = 'analyst@otshield.com'  AND is_admin IS NOT TRUE;
UPDATE users SET role = 'ROLE_OPERATOR'
  WHERE lower(email) = 'operator@otshield.com' AND is_admin IS NOT TRUE;

-- 3. Normalise any remaining legacy ROLE_USER rows to the read-only VIEWER role so
--    the hierarchy (ADMIN > ANALYST > OPERATOR > VIEWER) resolves cleanly. (New
--    code tolerates ROLE_USER too, but canonicalising keeps the data clean.)
UPDATE users SET role = 'ROLE_VIEWER'
  WHERE role = 'ROLE_USER' AND is_admin IS NOT TRUE;
