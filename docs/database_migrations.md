# Database Migrations

This project now uses Alembic for schema management.

## Files

- `alembic.ini` — Alembic entry config
- `backend/alembic/env.py` — runtime DB connection + metadata wiring
- `backend/alembic/versions/0001_initial_schema.py` — baseline schema migration

## Common commands

Run from the repository root:

```bash
alembic upgrade head
alembic downgrade -1
alembic revision --autogenerate -m "add column xxx"
```

## Recommended workflow

1. Modify ORM models in `backend/app/models/models.py`
2. Generate or edit a migration in `backend/alembic/versions/`
3. Run `alembic upgrade head`
4. Keep `backend/app/models/models.py` and migrations in sync

## Notes

- `backend/app/main.py` still has a development convenience `init_db()` fallback.
- Alembic is the source of truth for schema evolution.
- Existing databases can be brought under Alembic control with `alembic upgrade head` because the baseline migration is idempotent.
