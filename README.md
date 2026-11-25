# AccessHub — Employee Application Access Register

A small Flask + SQLite application based on the Employee Application Access Register spreadsheet. Includes employee directory, application catalogue, individual access assignments, dates and approvers, dashboard, search/filter, audit log, CSV export and administrator login.

## Run on Windows (recommended for first test)

1. Install Python 3.11+ from https://python.org (enable **Add Python to PATH**).
2. Extract this ZIP and open Command Prompt in the `employee_access_flask` directory.
3. Run:

   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   python app.py
   ```
4. Open **http://127.0.0.1:5000/setup**. Create your first administrator (password must have 12+ characters).
5. Sign in. Create employees, verify the preloaded app catalogue, then record access assignments.

All data goes into `access_register.db` (created automatically in this folder). Back it up securely. Do not commit it to Git.

## Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Important deployment and security notes

- **Prototype / internal MVP, not a production IAM platform.** It does not provision or revoke real access in CRM, MT5, payment gateways, or third-party systems.
- First run setup must be completed by the intended administrator before making the service available on a network.
- Run behind HTTPS and a reverse proxy, set `SECRET_KEY` to a long securely generated value, `COOKIE_SECURE=1` and disable public access to `/setup` once configured. Prefer corporate SSO/MFA and an approved identity provider before organisation-wide deployment.
- Use firewall/VPN restrictions, encrypted storage and backups, role-based authorization, proper retention and logging controls before production use.
- This starter app supports **one shared administrator privilege level** (all signed-in accounts have full control). It creates one account through initial setup; additional account management is not implemented.
- Audit logging records who changed a record and a short summary, not full before/after values. Review this before relying on it for compliance audits.
- Access revocation in the app updates the register only. IT must separately revoke access in the external system.
- If an employee leaves, set them to `Exited` and review/revoke their assignments manually. No auto-revocation is implemented.
- Exported CSV files contain employee data; store them safely.
- **For deployment behind a proxy**, use Waitress or a production WSGI server, not Flask's built-in development server. Example:

  ```bash
  waitress-serve --listen=127.0.0.1:8080 app:app
  ```
  For Waitress production startup initialize the database first: `python -c "from app import init_db; init_db()"`.
- No live integrations or automatic XLSX importing are included. Export to CSV is supported.

## Directory structure

- `app.py` — database schema, authentication and routes
- `templates/` — HTML pages
- `static/style.css` — responsive UI theme
- `requirements.txt` — Flask and Waitress
- `access_register.db` — automatically generated local database

## Sample workflow

Create employee `EMP001` → select `MT5` → `Read Only` → `Active` → set grant and review dates → record approving manager and IT ticket.

## Employee and application management (v2)

- **Edit:** Update employees and applications from their list views.
- **Disable / Enable:** An IT administrator can toggle each record. Disabling suspends active/pending assignment records, and disabled apps are excluded from new access assignment selection. Previously suspended assignments are **not** automatically reactivated when enabled again. An exited employee's assignments also become suspended when their details are saved.
- **Delete:** Permanent deletion is available only when the employee or application has **zero historical access assignments**. Linked records are protected so access audit history cannot accidentally be lost. Disable records instead if they have access history.
- **Existing database:** The application automatically adds the application status field to an older SQLite database at startup. **Back up `access_register.db` before upgrading.** Existing data is preserved.
- **Important:** These controls update the internal registry only, and do not provision, disable or delete user accounts in connected systems.

## Version 3 — User roles, departments, employee codes, and reporting chart

**Upgrade:** Back up the existing `access_register.db`, extract this ZIP and replace the application source/templates/static assets, retain the database, and run `python app.py` (or call `init_db()` once if deploying under Waitress). The database migration adds role/enable fields to existing system users, a department catalogue, reporting-manager relations, and a permanent employee-code reservation table. Existing user accounts are migrated as **Super Admin** to avoid unintentionally locking out prior administrators; review and adjust their roles immediately under **System Users**.

**System user login roles:**

- **Super Admin:** Can add/edit/disable login accounts, reset their passwords, and manage employees, applications, access assignments, and departments.
- **Admin:** Can create/edit/disable employees and applications, manage departments, edit/revoke access assignments, review records and export access data. Cannot edit login roles or accounts.
- **Read Only:** Can sign in to view the dashboard, employees, applications, access assignments, departments, reporting chart and audit log. Cannot modify information or export CSV data. Restrictions are enforced on the server, not just by hiding buttons.

To add a new administrator: sign in as a Super Admin → **System Users** → **Add System User** → specify login username, strong password, role, and enabled status. Accounts can be disabled; a Super Admin cannot disable or demote their own account, and the last enabled Super Admin must remain active. Employee application access levels (such as MT5 Manager Read Only) are separate from AccessHub login roles.

**Employee management:** Go to **Departments** to create departments, then go to **Employees** to add and filter people by department. Every employee has a required department, an optional reporting manager selected from existing active employees, and a unique employee code. Leave the code blank to auto-generate an `EMP000001`-style sequential code, or supply a custom code such as `IT-001`. Codes are permanently immutable and are never available for reuse, even after deletion. Reporting manager cycles and self-reporting are blocked. Employees with direct reports cannot be deleted until reports are reassigned.

**On-demand organisation chart:** Open **Reporting Chart** and select an employee (shows the entire chain up to their manager and immediate direct reports) or a department (interactive hierarchical tree for employees in that department). The chart remains hidden until a selection is made. Names from the old free-text reporting-manager field are automatically linked to employee records only when an exact unique match exists; verify and correct unmatched names by editing employees.

**Important operational safeguards:** Disabling employees in this inventory does not disable logins at external PSP, MT5, CRM, Sumsub, or other systems. Actual application access needs to be revoked separately. This app has password-based authentication but not MFA, SSO, login throttling, password-recovery workflows, or centrally managed encryption; it is intended as an internal MVP and must not be internet-exposed without security hardening, HTTPS, strong configuration, backups, and appropriate review. If used with real employee records, restrict network and filesystem access. System role changes and employee changes are recorded in the audit log.

**Testing note:** The Python modules were syntax-checked, every HTML template was parsed by Jinja2, and database initialization/migration was validated against new and legacy SQLite schemas. A complete live Flask HTTP test was not run in the build environment because Flask was not installed and package downloads were unavailable.


## V4 — Employee asset attachments
- Employees → **View** dropdown → **Reporting chart** or **Asset documents**.
- Admin and Super Admin: upload/delete PDF, DOCX, JPG or PNG (max 10MB). Read Only: view/download.
- Each uploaded file belongs to one employee and is stored under a generated filename; employee deletion is blocked while attachments exist.
- **Render persistent disk required:** mount a disk at `/opt/render/project/src/storage`, and set both `DATABASE_PATH=/opt/render/project/src/storage/access_register.db` and `UPLOAD_DIR=/opt/render/project/src/storage/uploads`.
- Existing database will automatically add the `employee_documents` table. **Back up your database and storage before upgrading.**
- Files in the old ephemeral filesystem are not migrated automatically.
- Production: keep a single Gunicorn worker with SQLite, protect the host and user accounts (MFA or identity provider recommended), regularly back up database + upload directory, and verify UAE data-residency requirements.
