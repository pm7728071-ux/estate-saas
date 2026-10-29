# estate-saas

Multi-tenant property-management service (Aegis Estate, Day 2 build).
Separate from the agent CRM (`estate-ai-agent-crm`) so the working agent loop is never put at risk.

## Status — foundation slice only (verified)

Implemented and covered by `npm test` (12/12 passing):

- Agencies, users (roles: owner / manager / agent), properties, tenants, sessions, audit collections
- Password auth with scrypt + per-user salt; opaque session tokens stored as SHA-256 hashes, 12h TTL
- `requireAuth`, `requireWrite` (owner/manager), agency scoping on every read and write
- Cross-agency isolation: list filtering, direct-id 404, foreign-property tenant rejection
- Append-only audit events for signup, login, property and tenant creation

## NOT implemented yet (do not assume otherwise)

- **Rent ledger and arrears** — no payments collection endpoints, no balance math, no partial payments
- **Dashboard UI** — no pages, no loading/empty/error states
- **Migrations** — indexes are created on boot; no versioned migration runner
- **Mongo path untested** — code branches on `MONGODB_URI` but only the in-memory driver has been
  exercised. It must be verified against a real cluster before any deployment claim.
- Payments indexes exist in the driver but no payment code reads them yet

## Run

```bash
npm install
npm test          # foundation suite (in-memory)
npm start         # http://localhost:3100
```

## Design notes

- Every record carries `agencyId` except agencies themselves. Filters always include it.
- Corrections will be new records referencing the original; financial history is never overwritten.
- Duplicate payment references will be enforced per agency + provider by a unique index.
