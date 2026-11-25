# AccessHub V4 — Update on Render

## Upgrade without losing employee records
1. **Back up** `access_register.db` and any existing `storage/` data before changing the service.
2. Extract this ZIP. Upload the **contents** of this folder to your **private** GitHub repository root (or set Render Root Directory to its location).
3. Keep the current Build Command: `pip install -r requirements.txt`.
4. Keep the Start Command: `gunicorn --workers 1 --bind 0.0.0.0:$PORT wsgi:app`.
5. Use a paid Render Web Service with a persistent disk mounted at `/opt/render/project/src/storage`.
6. Set environment variables:
   - `DATABASE_PATH=/opt/render/project/src/storage/access_register.db`
   - `UPLOAD_DIR=/opt/render/project/src/storage/uploads`
   - `SECRET_KEY=<your existing stable secret; do not post it publicly>`
   - `COOKIE_SECURE=1`
7. Redeploy the latest commit. The `employee_documents` table is created automatically when `wsgi.py` runs `init_db()`.
8. Open Employees → View → Asset documents and upload a test PDF as an Admin. Sign in as Read Only to verify that view/download works but upload/delete is hidden and blocked.

## Notes
- A PDF/JPG/PNG can be **viewed** in a new tab. DOCX files are available to **download**, not previewed in-browser.
- Attached documents are accessible only after authentication. Upload/delete requires Admin or Super Admin.
- Disabling an employee does not delete their documents. Employees with attached documents cannot be deleted until documents are removed.
- Do **not** store uploads in a temporary Render filesystem; they will vanish when the service redeploys.
- The app uses SQLite and a single Gunicorn worker; use PostgreSQL plus object storage for higher-volume or multi-instance production.
- Keep strict control of access to sensitive employee documents, make backups of both database and uploaded files, and get compliance approval for where the data is hosted.
