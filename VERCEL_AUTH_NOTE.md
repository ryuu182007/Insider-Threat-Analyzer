# Vercel authentication fix

Vercel uses serverless functions, so SQLite `/tmp` storage cannot be used as a persistent session store. The deployed build therefore uses signed stateless bearer tokens for authentication while still checking the employee record in SQLite on every request.

Optional Vercel environment variable:

`THREATSIM_SESSION_SECRET` = a long random secret. If omitted, the app derives a stable signing key from the configured admin password for demo compatibility.

For a production multi-instance deployment with persistent data, move the application database to a hosted PostgreSQL/MySQL service and use a persistent session/revocation store.
