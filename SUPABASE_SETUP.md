# Supabase + Vercel backend setup

This project can still run locally with SQLite. When `SUPABASE_DB_URL` (or `DATABASE_URL`) is present, the Flask backend uses Supabase Postgres instead.

## 1. Get the Supabase connection string

In the Supabase Dashboard, open **Connect** and choose the **Transaction pooler** for a serverless/Vercel deployment. Copy the PostgreSQL URI and replace `[YOUR-PASSWORD]` with the database password. Keep the password private.

For Vercel, the transaction pooler is the preferred choice because serverless functions create short-lived connections.

## 2. Add the Vercel environment variable

Vercel → Project → Settings → Environment Variables:

- Name: `SUPABASE_DB_URL`
- Value: your complete Supabase PostgreSQL connection string
- Environments: **Production** (also Preview if you want previews to use Supabase)

Do NOT put this connection string in frontend JavaScript or commit it to GitHub.

## 3. Migrate the existing SQLite data

From your local project, install dependencies and run:

```bash
pip install -r requirements.txt
```

Then set `SUPABASE_DB_URL` locally and run:

```bash
python database/migrate_sqlite_to_supabase.py
```

This copies the existing `database/insider_threat.db` tables and data into Supabase.

## 4. Redeploy Vercel

After adding the environment variable, create a new deployment/redeploy. The backend will automatically create the required tables if they do not exist.

## Notes

- Supabase Postgres becomes the persistent database for users, activity logs, incidents, simulations and tasks.
- The existing stateless Vercel login token remains in use; it does not depend on ephemeral SQLite sessions.
- Local development without `SUPABASE_DB_URL` continues to use SQLite.
