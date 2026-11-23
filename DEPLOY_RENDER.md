# AccessHub V3 — Deploy on Render

## 0. Production prerequisites
- Keep the GitHub repository private.
- Do not commit a database file, secrets, or employee information.
- Use a paid Render Web Service with an attached **persistent disk** for SQLite; the free instance loses local changes across deploys/restarts.
- For sensitive employee/privileged-access records, obtain your organisation's security/compliance approval before using any external hosting provider. Review data residency, backups, access controls and retention requirements.
- V3 does not include MFA, enterprise SSO, IP allowlisting or automated backups. Add these before broad production rollout.

## 1. GitHub
Create a private repository. Upload the *contents* of this directory so `app.py`, `wsgi.py`, `requirements.txt`, and `templates/` sit at the repository root.

## 2. Render Web Service
1. Open https://dashboard.render.com and select New > Web Service.
2. Connect the private GitHub repository.
3. Set Language/Runtime: Python.
4. Set Build Command: `pip install -r requirements.txt`
5. Set Start Command: `gunicorn --workers 1 --bind 0.0.0.0:$PORT wsgi:app`
6. Choose a paid plan compatible with persistent disks.
7. Add a persistent disk, e.g. mount path: `/opt/render/project/src/storage` (create as needed).
8. Set environment variables:
   - `DATABASE_PATH=/opt/render/project/src/storage/access_register.db`
   - `SECRET_KEY=<strong random secret of at least 32 bytes>`
   - `COOKIE_SECURE=1`
   - `PYTHON_VERSION=3.12.8` (or a current supported Python version)
9. Deploy. Open your HTTPS service URL, visit `/setup`, create the **first Super Admin** immediately.
10. Confirm records survive a deploy/restart. Set up off-platform database backups and test recovery.

## 3. Existing SQLite data
The new deployment creates a fresh database on the persistent disk. To migrate existing data, upload a consistent backup of `access_register.db` to the mounted disk **before the first production startup**; stop writes during backup. Do not upload the database to GitHub. If no existing records are needed, let the app initialize a new DB.

## 4. Important limitations
- The application is a tracking register and does NOT automatically provision/revoke actual application access.
- SQLite with a persistent disk is suitable for small, single-instance deployments. Do not run multiple replicas against the same file. A move to PostgreSQL would require application changes because the code uses `sqlite3` directly.
- Gunicorn runs the WSGI entrypoint; this is necessary because `python app.py`'s `init_db()` is otherwise under `if __name__ == '__main__'`.
- Before production use, add rate limiting, MFA/SSO, robust backups, monitoring, privacy controls, and complete security testing.
