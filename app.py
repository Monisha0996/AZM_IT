"""Employee Application Access Register — Flask + SQLite.
Run `python app.py` after installing requirements.
"""
import os, csv, io, sqlite3, secrets, uuid, zipfile
from pathlib import Path
from datetime import date, datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Response, send_file
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", os.path.join(BASE, "uploads"))).resolve()
MAX_UPLOAD = 10 * 1024 * 1024
ALLOWED_FILE_TYPES = {".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
DB = os.environ.get('DATABASE_PATH', os.path.join(BASE, 'access_register.db'))
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','0') == '1', MAX_CONTENT_LENGTH=MAX_UPLOAD + 128 * 1024)
LEVELS = ['Read Only','Standard User','Power User','Manager','Admin','Super Admin']
STATUSES = ['Active','Pending','Suspended','Revoked']
EMP_STATUSES = ['Active','On Leave','Exited','Disabled']
SENSITIVITIES = ['Internal','Confidential','Restricted']
ROLES = ['Super Admin', 'Admin', 'Read Only']

def conn():
    db=sqlite3.connect(DB)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def init_db():
    with conn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Super Admin', enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY, employee_code TEXT NOT NULL UNIQUE, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, department TEXT, title TEXT, manager TEXT, status TEXT NOT NULL DEFAULT 'Active', notes TEXT);
        CREATE TABLE IF NOT EXISTS applications (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, category TEXT, owner TEXT, vendor TEXT, sensitivity TEXT NOT NULL DEFAULT 'Confidential', notes TEXT, status TEXT NOT NULL DEFAULT 'Active');
        CREATE TABLE IF NOT EXISTS assignments (id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE RESTRICT, application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE RESTRICT, access_level TEXT NOT NULL, scope TEXT, status TEXT NOT NULL DEFAULT 'Pending', granted_on TEXT, reviewed_on TEXT, review_due TEXT, approved_by TEXT, ticket TEXT, UNIQUE(employee_id, application_id));
        CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS employee_documents (
            id INTEGER PRIMARY KEY,
            employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE RESTRICT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            doc_type TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_documents_employee ON employee_documents(employee_id);
        CREATE TABLE IF NOT EXISTS used_employee_codes (code TEXT PRIMARY KEY, first_used TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL, detail TEXT);
        CREATE INDEX IF NOT EXISTS ix_assign_status ON assignments(status);
        CREATE INDEX IF NOT EXISTS ix_review_due ON assignments(review_due);
        ''')
        # Preserve existing data while upgrading v1/v2 databases.
        usercols={r['name'] for r in db.execute('PRAGMA table_info(users)')}
        if 'role' not in usercols: db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'Super Admin'")
        if 'enabled' not in usercols: db.execute('ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1')
        empcols={r['name'] for r in db.execute('PRAGMA table_info(employees)')}
        if 'manager_id' not in empcols: db.execute('ALTER TABLE employees ADD COLUMN manager_id INTEGER REFERENCES employees(id) ON DELETE SET NULL')
        # Old manager text is retained. Match exact employee names only when unique.
        for e in db.execute("SELECT id,manager FROM employees WHERE manager_id IS NULL AND trim(coalesce(manager,''))!=''").fetchall():
            matches=db.execute('SELECT id FROM employees WHERE lower(name)=lower(?) AND id!=?',(e['manager'].strip(),e['id'])).fetchall()
            if len(matches)==1: db.execute('UPDATE employees SET manager_id=? WHERE id=?',(matches[0]['id'],e['id']))
        db.execute("INSERT OR IGNORE INTO used_employee_codes(code,first_used) SELECT upper(employee_code),datetime('now') FROM employees")
        db.execute("INSERT OR IGNORE INTO departments(name) SELECT DISTINCT trim(department) FROM employees WHERE trim(coalesce(department,'')) != ''")
        # Migrate databases created by the original version without losing records.
        columns={r['name'] for r in db.execute('PRAGMA table_info(applications)')}
        if 'status' not in columns:
            db.execute("ALTER TABLE applications ADD COLUMN status TEXT NOT NULL DEFAULT 'Active'")
        if db.execute('SELECT COUNT(*) FROM applications').fetchone()[0]==0:
            initial=[('CRM / Client Portal','Brokerage Operations','Restricted'),('MetaTrader 5 (MT5)','Trading Platform','Restricted'),('Sumsub','KYC / AML','Restricted'),('Checkout.com','Payment Service Provider','Restricted'),('Network International','Payment Service Provider','Restricted'),('MyFatoorah','Payment Service Provider','Restricted'),('Microsoft 365 / Email','Collaboration','Confidential'),('3CX','Communications','Confidential'),('Jira','IT Service Desk','Internal')]
            db.executemany('INSERT INTO applications(name,category,sensitivity) VALUES (?,?,?)',initial)

def audit(db, action, entity, detail=''):
    db.execute('INSERT INTO audit(timestamp,actor,action,entity,detail) VALUES (?,?,?,?,?)',(datetime.now().isoformat(timespec='seconds'),session.get('username','system'),action,entity,detail[:500]))

@app.before_request
def ensure_user_still_active():
    if session.get('user_id'):
        with conn() as db:
            u=db.execute('SELECT username,role,enabled FROM users WHERE id=?',(session['user_id'],)).fetchone()
        if not u or not u['enabled']:
            session.clear()
            return redirect(url_for('login'))
        session['role']=u['role']
        session['username']=u['username']

@app.before_request
def csrf_check():
    if request.method in ('POST','PUT','PATCH','DELETE'):
        token=request.form.get('_csrf')
        if not token or not secrets.compare_digest(token,session.get('_csrf','')):
            abort(400,description='Invalid security token. Refresh the page and try again.')

@app.context_processor
def common():
    if '_csrf' not in session: session['_csrf']=secrets.token_urlsafe(32)
    return dict(csrf_token=session['_csrf'], can_edit=can_edit(), is_super=current_role()=='Super Admin', user_role=current_role(), levels=LEVELS, statuses=STATUSES, employee_statuses=EMP_STATUSES, sensitivities=SENSITIVITIES, today=date.today().isoformat())

def current_role():
    return session.get('role','Read Only')

def can_edit():
    return current_role() in ('Admin','Super Admin')

def edit_required(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if not can_edit(): abort(403, description='Read-only account: changes are not permitted.')
        return fn(*args, **kwargs)
    return inner

def super_required(fn):
    @wraps(fn)
    @login_required
    def inner(*args, **kwargs):
        if current_role()!='Super Admin':abort(403, description='Super Admin access required.')
        return fn(*args, **kwargs)
    return inner

def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return fn(*args,**kwargs)
    return inner

@app.route('/setup',methods=['GET','POST'])
def setup():
    with conn() as db:
        if db.execute('SELECT COUNT(*) FROM users').fetchone()[0]:abort(404)
        if request.method=='POST':
            username=request.form.get('username','').strip()
            password=request.form.get('password','')
            if len(username)<3 or len(password)<12:
                flash('Use a username of at least 3 characters and password of at least 12 characters.','error')
            else:
                db.execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',(username,generate_password_hash(password),'Super Admin'))
                flash('Administrator created. Sign in to continue.','success')
                return redirect(url_for('login'))
    return render_template('auth.html',setup=True)

@app.route('/login',methods=['GET','POST'])
def login():
    with conn() as db:
        if not db.execute('SELECT COUNT(*) FROM users').fetchone()[0]:return redirect(url_for('setup'))
        if request.method=='POST':
            user=db.execute('SELECT * FROM users WHERE username=?',(request.form.get('username','').strip(),)).fetchone()
            if user and user['enabled'] and check_password_hash(user['password_hash'],request.form.get('password','')):
                session.clear();session['user_id']=user['id'];session['username']=user['username'];session['role']=user['role'];session['_csrf']=secrets.token_urlsafe(32)
                return redirect(url_for('dashboard'))
            flash('Invalid username or password.','error')
    return render_template('auth.html',setup=False)

@app.post('/logout')
@login_required
def logout():
    session.clear();return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    with conn() as db:
        counts={k:db.execute(q).fetchone()[0] for k,q in {
            'employees':"SELECT COUNT(*) FROM employees WHERE status='Active'",'applications':"SELECT COUNT(*) FROM applications WHERE status='Active'",
            'active':"SELECT COUNT(*) FROM assignments WHERE status='Active'",'pending':"SELECT COUNT(*) FROM assignments WHERE status='Pending'",'overdue':"SELECT COUNT(*) FROM assignments WHERE status='Active' AND review_due IS NOT NULL AND review_due < date('now')"}.items()}
        recent=db.execute('''SELECT a.*,e.name employee,e.email, p.name application FROM assignments a JOIN employees e ON e.id=a.employee_id JOIN applications p ON p.id=a.application_id ORDER BY a.id DESC LIMIT 8''').fetchall()
        due=db.execute('''SELECT a.*,e.name employee,p.name application FROM assignments a JOIN employees e ON e.id=a.employee_id JOIN applications p ON p.id=a.application_id WHERE a.status='Active' AND a.review_due IS NOT NULL AND a.review_due <=date('now','+30 day') ORDER BY a.review_due LIMIT 8''').fetchall()
    return render_template('dashboard.html',counts=counts,recent=recent,due=due)

@app.route('/employees')
@login_required
def employees():
    q=request.args.get('q','').strip(); department=request.args.get('department','').strip()
    with conn() as db:
        departments=db.execute('SELECT name FROM departments ORDER BY name').fetchall()
        rows=db.execute("""SELECT e.*,m.name manager_name, COUNT(a.id) total_access,
            (SELECT COUNT(*) FROM assignments t WHERE t.employee_id=e.id) total_assignments,
            (SELECT COUNT(*) FROM employees x WHERE x.manager_id=e.id) direct_reports,
            (SELECT COUNT(*) FROM employee_documents d WHERE d.employee_id=e.id) document_count
            FROM employees e LEFT JOIN employees m ON m.id=e.manager_id
            LEFT JOIN assignments a ON a.employee_id=e.id AND a.status='Active'
            WHERE (e.name LIKE ? OR e.email LIKE ? OR e.employee_code LIKE ?)
            AND (?='' OR e.department=?) GROUP BY e.id ORDER BY e.department,e.name""",
            ('%'+q+'%',)*3+(department,department)).fetchall()
    return render_template('employees.html',rows=rows,q=q,department=department,departments=departments)

@app.route('/employees/new',methods=['GET','POST'])
@app.route('/employees/<int:item_id>/edit',methods=['GET','POST'])
@edit_required
def employee_form(item_id=None):
    with conn() as db:
        item=db.execute('SELECT * FROM employees WHERE id=?',(item_id,)).fetchone() if item_id else None
        if item_id and not item:abort(404)
        departments=db.execute('SELECT * FROM departments ORDER BY name').fetchall()
        managers=db.execute("SELECT id,name,employee_code,department FROM employees WHERE status NOT IN ('Disabled','Exited') AND id != ? ORDER BY name",(item_id or -1,)).fetchall()
        if request.method=='POST':
            code=request.form.get('employee_code','').strip().upper()
            name=request.form.get('name','').strip();email=request.form.get('email','').strip().lower()
            department=request.form.get('department','').strip()
            title=request.form.get('title','').strip();status=request.form.get('status','').strip()
            notes=request.form.get('notes','').strip();mid=request.form.get('manager_id','').strip()
            if item:code=item['employee_code']  # immutable after creation; POST tampering is ignored
            elif not code:
                # Monotonically incremented auto-generated codes, never reuse deleted codes.
                prior=[r['code'] for r in db.execute("SELECT code FROM used_employee_codes WHERE code LIKE 'EMP%'")]
                seq=max([int(x[3:]) for x in prior if x[3:].isdigit()] or [0])+1
                code=f'EMP{seq:06d}'
                while db.execute('SELECT 1 FROM used_employee_codes WHERE upper(code)=?',(code,)).fetchone():
                    seq+=1;code=f'EMP{seq:06d}'
            manager_id=int(mid) if mid.isdigit() else None
            if not code or len(code)>40 or not name or '@' not in email or status not in EMP_STATUSES or not department:
                flash('Employee code, name, work email, department and valid status are required.','error')
            elif not db.execute('SELECT 1 FROM departments WHERE name=?',(department,)).fetchone():
                flash('Select a valid department from the list.','error')
            elif mid and not manager_id:
                flash('Select a valid reporting manager.','error')
            elif manager_id and not db.execute('SELECT 1 FROM employees WHERE id=?',(manager_id,)).fetchone():
                flash('Reporting manager does not exist.','error')
            elif item_id and manager_id==item_id:
                flash('An employee cannot report to themselves.','error')
            elif manager_id and item_id and reporting_cycle(db,item_id,manager_id):
                flash('This manager would create a reporting cycle. Choose another manager.','error')
            elif not item and db.execute('SELECT 1 FROM used_employee_codes WHERE upper(code)=?',(code.upper(),)).fetchone():
                flash('Employee code has been used before. Codes cannot be reused, even after deletion.','error')
            else:
                try:
                    manager_name=db.execute('SELECT name FROM employees WHERE id=?',(manager_id,)).fetchone()['name'] if manager_id else ''
                    if item_id:
                        db.execute('UPDATE employees SET name=?,email=?,department=?,title=?,manager=?,manager_id=?,status=?,notes=? WHERE id=?',(name,email,department,title,manager_name,manager_id,status,notes,item_id))
                    else:
                        db.execute('INSERT INTO employees(employee_code,name,email,department,title,manager,manager_id,status,notes) VALUES (?,?,?,?,?,?,?,?,?)',(code,name,email,department,title,manager_name,manager_id,status,notes))
                        db.execute("INSERT INTO used_employee_codes(code,first_used) VALUES (?,datetime('now'))",(code.upper(),))
                    if item_id and status in ('Disabled','Exited'):
                        db.execute("UPDATE assignments SET status='Suspended' WHERE employee_id=? AND status IN ('Active','Pending')",(item_id,))
                    audit(db,'Updated' if item_id else 'Created','Employee',code)
                    return redirect(url_for('employees',department=department))
                except sqlite3.IntegrityError:flash('Employee code or work email already exists.','error')
    return render_template('employee_form.html',item=item,departments=departments,managers=managers)

def reporting_cycle(db,employee_id,manager_id):
    seen={employee_id}
    while manager_id:
        if manager_id in seen:return True
        seen.add(manager_id)
        row=db.execute('SELECT manager_id FROM employees WHERE id=?',(manager_id,)).fetchone()
        manager_id=row['manager_id'] if row else None
    return False

@app.route('/applications')
@login_required
def applications():
    with conn() as db:
        rows=db.execute('''SELECT p.*,COUNT(a.id) active_users, (SELECT COUNT(*) FROM assignments t WHERE t.application_id=p.id) total_assignments FROM applications p LEFT JOIN assignments a ON a.application_id=p.id AND a.status='Active' GROUP BY p.id ORDER BY p.name''').fetchall()
    return render_template('applications.html',rows=rows)

@app.route('/applications/new',methods=['GET','POST'])
@app.route('/applications/<int:item_id>/edit',methods=['GET','POST'])
@edit_required
def application_form(item_id=None):
    with conn() as db:
        item=db.execute('SELECT * FROM applications WHERE id=?',(item_id,)).fetchone() if item_id else None
        if item_id and not item:abort(404)
        if request.method=='POST':
            data=[request.form.get(k,'').strip() for k in ('name','category','owner','vendor','sensitivity','notes','status')]
            if not data[0] or data[4] not in SENSITIVITIES or data[6] not in ('Active','Disabled'):flash('Application name, sensitivity and status are required.','error')
            else:
                try:
                    if item_id:db.execute('UPDATE applications SET name=?,category=?,owner=?,vendor=?,sensitivity=?,notes=?,status=? WHERE id=?',(*data,item_id))
                    else:db.execute('INSERT INTO applications(name,category,owner,vendor,sensitivity,notes,status) VALUES (?,?,?,?,?,?,?)',data)
                    if item_id and data[6]=='Disabled':
                        db.execute("UPDATE assignments SET status='Suspended' WHERE application_id=? AND status IN ('Active','Pending')",(item_id,))
                    audit(db,'Updated' if item_id else 'Created','Application',data[0]);return redirect(url_for('applications'))
                except sqlite3.IntegrityError:flash('Application name already exists.','error')
    return render_template('application_form.html',item=item)


# Status changes only affect this register, never the actual external application.
def set_enabled(kind, item_id, enable):
    table = 'employees' if kind == 'Employee' else 'applications'
    fk = 'employee_id' if kind == 'Employee' else 'application_id'
    with conn() as db:
        item=db.execute(f'SELECT id,name,status FROM {table} WHERE id=?',(item_id,)).fetchone()
        if not item:abort(404)
        target='Active' if enable else 'Disabled'
        if item['status']==target:
            flash(f'{kind} is already {target.lower()}.','success')
        else:
            db.execute(f'UPDATE {table} SET status=? WHERE id=?',(target,item_id))
            if not enable:
                # Do not leave documented active access assigned to a disabled entity.
                count=db.execute(f"UPDATE assignments SET status='Suspended' WHERE {fk}=? AND status IN ('Active','Pending')",(item_id,)).rowcount
            else:count=0
            audit(db,'Enabled' if enable else 'Disabled',kind,f'{item["name"]} (ID {item_id}); {count} assignments suspended')
            flash(f'{kind} {"enabled" if enable else "disabled"}. '+('Previously suspended assignments remain suspended pending review. ' if enable else '')+'Update actual permissions in external systems separately.','success')
    return redirect(url_for(table))

@app.post('/employees/<int:item_id>/toggle')
@edit_required
def toggle_employee(item_id):
    return set_enabled('Employee',item_id,request.form.get('action')=='enable')

@app.post('/applications/<int:item_id>/toggle')
@edit_required
def toggle_application(item_id):
    return set_enabled('Application',item_id,request.form.get('action')=='enable')

def delete_record(kind,item_id):
    table='employees' if kind=='Employee' else 'applications'
    fk='employee_id' if kind=='Employee' else 'application_id'
    with conn() as db:
        item=db.execute(f'SELECT id,name FROM {table} WHERE id=?',(item_id,)).fetchone()
        if not item:abort(404)
        if request.form.get('confirm') != 'DELETE':
            flash('Deletion not confirmed.','error')
        elif kind=='Employee' and db.execute('SELECT 1 FROM employees WHERE manager_id=?',(item_id,)).fetchone():
            flash('Cannot delete this employee while other employees report to them. Reassign reports first.','error')
        elif kind=='Employee' and db.execute('SELECT 1 FROM employee_documents WHERE employee_id=?',(item_id,)).fetchone():
            flash('Cannot delete employee with attached documents. Disable the employee to preserve the archive, or delete attachments first.','error')
        elif db.execute(f'SELECT COUNT(*) FROM assignments WHERE {fk}=?',(item_id,)).fetchone()[0]:
            flash(f'Cannot delete {kind.lower()}: linked access history exists. Disable it instead to preserve audit records.','error')
        else:
            audit(db,'Deleted',kind,f'{item["name"]} (ID {item_id})')
            db.execute(f'DELETE FROM {table} WHERE id=?',(item_id,))
            flash(f'{kind} deleted permanently.','success')
    return redirect(url_for(table))

@app.post('/employees/<int:item_id>/delete')
@edit_required
def delete_employee(item_id):
    return delete_record('Employee',item_id)

@app.post('/applications/<int:item_id>/delete')
@edit_required
def delete_application(item_id):
    return delete_record('Application',item_id)

# Asset allocation and supporting documents (viewable by all authorised users).
def valid_document(file_obj, suffix):
    """Check file signatures, not only browser-supplied MIME types."""
    file_obj.stream.seek(0)
    start = file_obj.stream.read(16)
    file_obj.stream.seek(0)
    if suffix == '.pdf': return start.startswith(b'%PDF-')
    if suffix == '.png': return start.startswith(b'\x89PNG\r\n\x1a\n')
    if suffix in ('.jpg', '.jpeg'): return start.startswith(b'\xff\xd8\xff')
    if suffix == '.docx':
        try:
            with zipfile.ZipFile(file_obj.stream) as z:
                return '[Content_Types].xml' in z.namelist() and 'word/document.xml' in z.namelist()
        except (zipfile.BadZipFile, OSError): return False
        finally: file_obj.stream.seek(0)
    return False

@app.route('/employees/<int:employee_id>/documents', methods=['GET', 'POST'])
@login_required
def employee_documents(employee_id):
    with conn() as db:
        employee = db.execute('SELECT * FROM employees WHERE id=?', (employee_id,)).fetchone()
        if not employee: abort(404)
        if request.method == 'POST':
            if not can_edit(): abort(403)
            uploaded = request.files.get('attachment')
            kind = request.form.get('doc_type', 'Asset Allocation').strip()
            allowed_kinds = ('Asset Allocation', 'Handover / Return', 'Other')
            if not uploaded or not uploaded.filename:
                flash('Choose a file to upload.', 'error')
            elif kind not in allowed_kinds:
                flash('Choose a valid document category.', 'error')
            else:
                filename = os.path.basename(uploaded.filename.replace('\\', '/')).strip()
                suffix = Path(filename).suffix.lower()
                if suffix not in ALLOWED_FILE_TYPES or not valid_document(uploaded, suffix):
                    flash('Use a valid PDF, DOCX, PNG, or JPG file.', 'error')
                else:
                    # Enforce actual file size even if the request Content-Length is unavailable.
                    uploaded.stream.seek(0, 2)
                    size = uploaded.stream.tell()
                    uploaded.stream.seek(0)
                    if not 0 < size <= MAX_UPLOAD:
                        flash('File must be between 1 byte and 10 MB.', 'error')
                    else:
                        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                        stored = uuid.uuid4().hex + suffix
                        dest = UPLOAD_DIR / stored
                        try:
                            uploaded.save(dest)
                            db.execute("""INSERT INTO employee_documents
                                (employee_id,original_name,stored_name,doc_type,mime_type,size_bytes,uploaded_by,uploaded_at)
                                VALUES (?,?,?,?,?,?,?,?)""",
                                (employee_id,filename[:200],stored,kind,ALLOWED_FILE_TYPES[suffix],size,session['username'],datetime.now().isoformat(timespec='seconds')))
                            audit(db,'Uploaded','Employee Document',f'{employee["employee_code"]}: {filename[:120]}')
                            flash('Document uploaded successfully.', 'success')
                        except Exception:
                            dest.unlink(missing_ok=True)
                            raise
                        return redirect(url_for('employee_documents', employee_id=employee_id))
        docs = db.execute('SELECT * FROM employee_documents WHERE employee_id=? ORDER BY uploaded_at DESC, id DESC', (employee_id,)).fetchall()
    return render_template('employee_documents.html', employee=employee, docs=docs)

@app.route('/employee-documents/<int:doc_id>/file')
@login_required
def employee_document_file(doc_id):
    with conn() as db:
        doc = db.execute('SELECT * FROM employee_documents WHERE id=?', (doc_id,)).fetchone()
    if not doc: abort(404)
    path = UPLOAD_DIR / doc['stored_name']
    if not path.is_file(): abort(404, description='The document file is missing from storage. Check persistent disk configuration.')
    inline = request.args.get('preview') == '1' and doc['mime_type'] in ('application/pdf', 'image/png', 'image/jpeg')
    response = send_file(path, mimetype=doc['mime_type'], as_attachment=not inline,
                         download_name=doc['original_name'], conditional=True)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'private, no-store'
    if inline:
        response.headers['Content-Security-Policy'] = 'sandbox'
    return response

@app.post('/employee-documents/<int:doc_id>/delete')
@edit_required
def delete_employee_document(doc_id):
    if request.form.get('confirm') != 'DELETE': abort(400)
    with conn() as db:
        doc = db.execute("""SELECT d.*, e.employee_code FROM employee_documents d
                           JOIN employees e ON e.id=d.employee_id WHERE d.id=?""", (doc_id,)).fetchone()
        if not doc: abort(404)
        db.execute('DELETE FROM employee_documents WHERE id=?', (doc_id,))
        audit(db,'Deleted','Employee Document',f'{doc["employee_code"]}: {doc["original_name"][:120]}')
        employee_id = doc['employee_id']
    (UPLOAD_DIR / doc['stored_name']).unlink(missing_ok=True)
    flash('Document deleted.', 'success')
    return redirect(url_for('employee_documents', employee_id=employee_id))

@app.route('/access')
@login_required
def access():
    q=request.args.get('q','').strip(); status=request.args.get('status','')
    with conn() as db:
        rows=db.execute('''SELECT a.*,e.name employee,e.email,p.name application FROM assignments a JOIN employees e ON e.id=a.employee_id JOIN applications p ON p.id=a.application_id WHERE (e.name LIKE ? OR e.email LIKE ? OR p.name LIKE ?) AND (?='' OR a.status=?) ORDER BY e.name,p.name''',('%'+q+'%',)*3+(status,status)).fetchall()
    return render_template('access.html',rows=rows,q=q,chosen_status=status)

@app.route('/access/new',methods=['GET','POST'])
@app.route('/access/<int:item_id>/edit',methods=['GET','POST'])
@edit_required
def access_form(item_id=None):
    with conn() as db:
        item=db.execute('SELECT * FROM assignments WHERE id=?',(item_id,)).fetchone() if item_id else None
        if item_id and not item:abort(404)
        employees=db.execute("SELECT * FROM employees WHERE status != 'Disabled' OR id=? ORDER BY name",(item['employee_id'] if item else -1,)).fetchall()
        apps=db.execute("SELECT * FROM applications WHERE status='Active' OR id=? ORDER BY name",(item['application_id'] if item else -1,)).fetchall()
        if request.method=='POST':
            keys=('employee_id','application_id','access_level','scope','status','granted_on','reviewed_on','review_due','approved_by','ticket')
            data=[request.form.get(k,'').strip() for k in keys]
            if data[2] not in LEVELS or data[4] not in STATUSES:flash('Select a valid access level and status.','error')
            elif not data[0].isdigit() or not data[1].isdigit():flash('Select an employee and application.','error')
            elif not db.execute("SELECT 1 FROM employees WHERE id=? AND status NOT IN ('Disabled','Exited')",(data[0],)).fetchone() or not db.execute("SELECT 1 FROM applications WHERE id=? AND status='Active'",(data[1],)).fetchone():
                flash('Cannot assign access to a disabled/exited employee or disabled application.','error')
            else:
                try:
                    for i in (5,6,7):
                        if data[i]:date.fromisoformat(data[i])
                    if item_id:db.execute('''UPDATE assignments SET employee_id=?,application_id=?,access_level=?,scope=?,status=?,granted_on=?,reviewed_on=?,review_due=?,approved_by=?,ticket=? WHERE id=?''',(*data,item_id))
                    else:db.execute('''INSERT INTO assignments(employee_id,application_id,access_level,scope,status,granted_on,reviewed_on,review_due,approved_by,ticket) VALUES (?,?,?,?,?,?,?,?,?,?)''',data)
                    audit(db,'Updated' if item_id else 'Assigned','Access',f'Employee {data[0]}, App {data[1]}, {data[2]}, {data[4]}')
                    return redirect(url_for('access'))
                except (sqlite3.IntegrityError,ValueError):flash('Duplicate assignment, invalid reference, or incorrect date.','error')
    return render_template('access_form.html',item=item,employees=employees,apps=apps)

@app.post('/access/<int:item_id>/revoke')
@edit_required
def revoke(item_id):
    with conn() as db:
        item=db.execute('SELECT id FROM assignments WHERE id=?',(item_id,)).fetchone()
        if not item:abort(404)
        db.execute("UPDATE assignments SET status='Revoked' WHERE id=?",(item_id,))
        audit(db,'Revoked','Access',str(item_id))
        flash('Access marked as revoked. Update the permission in the actual application separately.','success')
    return redirect(url_for('access'))

@app.route('/audit')
@login_required
def audits():
    with conn() as db:rows=db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200').fetchall()
    return render_template('audit.html',rows=rows)

@app.route('/export/access.csv')
@edit_required
def export_access():
    with conn() as db:
        rows=db.execute('''SELECT e.employee_code,e.name,e.email,e.department,e.title,p.name application,a.access_level,a.scope,a.status,a.granted_on,a.reviewed_on,a.review_due,a.approved_by,a.ticket FROM assignments a JOIN employees e ON e.id=a.employee_id JOIN applications p ON p.id=a.application_id ORDER BY e.name,p.name''').fetchall()
        audit(db,'Exported','Access CSV',f'{len(rows)} records')
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(['Employee ID','Name','Work Email','Department','Job Title','Application','Access Level','Permission / Scope','Status','Granted On','Last Reviewed','Review Due','Approved By','Comments / Ticket'])
    for row in rows:
        # Guard against CSV formula injection when opened in Excel
        writer.writerow(["'"+str(v) if isinstance(v,str) and v[:1] in ('=','+','-','@') else v for v in tuple(row)])
    return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=employee_access_register.csv'})

@app.route('/departments',methods=['GET','POST'])
@login_required
def departments():
    with conn() as db:
        if request.method=='POST':
            if not can_edit():abort(403)
            name=request.form.get('name','').strip()
            if not name or len(name)>100: flash('Enter a department name (up to 100 characters).','error')
            else:
                try:
                    db.execute('INSERT INTO departments(name) VALUES (?)',(name,))
                    audit(db,'Created','Department',name)
                    flash('Department added.','success')
                except sqlite3.IntegrityError:flash('Department already exists.','error')
            return redirect(url_for('departments'))
        rows=db.execute('SELECT d.*,COUNT(e.id) headcount FROM departments d LEFT JOIN employees e ON e.department=d.name GROUP BY d.id ORDER BY d.name').fetchall()
    return render_template('departments.html',rows=rows)

@app.route('/org-chart')
@login_required
def org_chart():
    employee=request.args.get('employee','').strip();department=request.args.get('department','').strip()
    with conn() as db:
        departments=db.execute('SELECT name FROM departments ORDER BY name').fetchall()
        employees=db.execute('SELECT * FROM employees ORDER BY department,name').fetchall()
        selected=None; team=[]; chain=[]
        if employee.isdigit():
            selected=db.execute('SELECT * FROM employees WHERE id=?',(int(employee),)).fetchone()
            if selected:
                team=db.execute('SELECT * FROM employees WHERE manager_id=? ORDER BY name',(selected['id'],)).fetchall()
                cursor=selected['manager_id'];visited={selected['id']}
                while cursor and cursor not in visited:
                    visited.add(cursor)
                    m=db.execute('SELECT * FROM employees WHERE id=?',(cursor,)).fetchone()
                    if not m:break
                    chain.insert(0,m);cursor=m['manager_id']
        group=[]; group_ids=set(); group_roots=[]
        if department:
            group=db.execute('SELECT * FROM employees WHERE department=? ORDER BY name',(department,)).fetchall()
            group_ids={r['id'] for r in group}
            group_roots=[r for r in group if r['manager_id'] not in group_ids]
        # Display only on explicit selection, never on the default page.
    return render_template('org_chart.html',employees=employees,departments=departments,selected=selected,team=team,chain=chain,group=group,group_ids=group_ids,group_roots=group_roots,chosen_department=department,chosen_employee=employee)

@app.route('/users')
@super_required
def users():
    with conn() as db:rows=db.execute('SELECT id,username,role,enabled FROM users ORDER BY username').fetchall()
    return render_template('users.html',rows=rows)

@app.route('/users/new',methods=['GET','POST'])
@app.route('/users/<int:item_id>/edit',methods=['GET','POST'])
@super_required
def user_form(item_id=None):
    with conn() as db:
        item=db.execute('SELECT id,username,role,enabled FROM users WHERE id=?',(item_id,)).fetchone() if item_id else None
        if item_id and not item:abort(404)
        if request.method=='POST':
            username=request.form.get('username','').strip()
            role=request.form.get('role','')
            password=request.form.get('password','')
            enabled=1 if request.form.get('enabled')=='1' else 0
            if len(username)<3 or role not in ROLES or (password and len(password)<12) or (not item and len(password)<12):
                flash('Enter a valid username, role, and password of at least 12 characters for new accounts or password changes.','error')
            elif item_id==session['user_id'] and (not enabled or role!='Super Admin'):
                flash('You cannot disable or demote your own Super Admin account.','error')
            elif item and item['role']=='Super Admin' and (not enabled or role!='Super Admin') and db.execute("SELECT COUNT(*) FROM users WHERE role='Super Admin' AND enabled=1").fetchone()[0]<=1:
                flash('At least one active Super Admin must remain.','error')
            else:
                try:
                    if item:
                        if password:db.execute('UPDATE users SET username=?,role=?,enabled=?,password_hash=? WHERE id=?',(username,role,enabled,generate_password_hash(password),item_id))
                        else:db.execute('UPDATE users SET username=?,role=?,enabled=? WHERE id=?',(username,role,enabled,item_id))
                    else:db.execute('INSERT INTO users(username,password_hash,role,enabled) VALUES (?,?,?,?)',(username,generate_password_hash(password),role,enabled))
                    audit(db,'Updated' if item else 'Created','System User',f'{username}: {role}; enabled={enabled}')
                    flash('System user saved.','success')
                    return redirect(url_for('users'))
                except sqlite3.IntegrityError:flash('Username already exists.','error')
    return render_template('user_form.html',item=item,roles=ROLES)

@app.post('/users/<int:item_id>/toggle')
@super_required
def toggle_user(item_id):
    if item_id==session['user_id']:abort(400,description='Cannot disable own account.')
    with conn() as db:
        item=db.execute('SELECT id,username,role,enabled FROM users WHERE id=?',(item_id,)).fetchone()
        if not item:abort(404)
        enabled=0 if item['enabled'] else 1
        if not enabled and item['role']=='Super Admin' and db.execute("SELECT COUNT(*) FROM users WHERE role='Super Admin' AND enabled=1").fetchone()[0]<=1:
            flash('At least one active Super Admin must remain.','error')
        else:
            db.execute('UPDATE users SET enabled=? WHERE id=?',(enabled,item_id))
            audit(db,'Enabled' if enabled else 'Disabled','System User',item['username'])
            flash('User status changed.','success')
    return redirect(url_for('users'))

if __name__=='__main__':
    init_db()
    app.run(host='127.0.0.1',port=int(os.getenv('PORT','5000')),debug=False)
