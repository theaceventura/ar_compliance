# Cybersecurity Awareness Compliance Tracker – HD Submission Outline

## 1. Problem definition
- Goal: Track mandatory cybersecurity awareness tasks for staff (password hygiene, phishing, etc.).
- Users: regular users, company admins, platform admins.
- Key needs: assign tasks (global or company-specific), users complete tasks via verification Q/A, track overdue, calculate compliance %, report per user/company, export CSV.

## 2. Assumptions
- A task may be global (applies to all companies) or scoped to one company.
- A completed assignment must not be removed from a user.
- Overdue = due_date < today for any incomplete assignment.
- Compliance (tasks): fully completed tasks ÷ total tasks in scope.
- Compliance (users): users with no pending/overdue tasks ÷ total users in scope.
- Data stored in SQLite (advanced feature). A JSON/CSV import/export path can be added if required.

## 3. Data model (SQLite)
- users(id, username, password_hash, role, company_id, is_active, contact fields…)
- companies(id, name, is_active, company_admin_id, address…)
- tasks(id, title, description, due_date, impact, severity, company_id NULL=global, verification_q/a)
- user_tasks(id, user_id, task_id, status, answer_text, completed_at)
- app_settings(id, version, UI toggles, chart palettes)

## 4. Core flows (pseudocode)

**Login**
```
on POST /login(username, password):
    user = db.find_user(username)
    if not user or !check_hash(password, user.password_hash):
         flash "invalid"
         return login
    session = {user_id, role, company_id}
    redirect to /dashboard (admin -> task dashboard)
```

**Ensure assignments (global/company)**
```
function ensure_assignments(company_id=None):
    tasks = all tasks where task.company_id is NULL or = company_id (if provided)
    users = all active users matching company_id or all companies if global
    for each (user, task) pair missing in user_tasks:
         insert pending assignment
```

**Complete a task**
```
on POST /task/<id>/answer(answer_text):
    assignment = user_tasks row for (session.user_id, task_id)
    if answer_text == task.verification_answer:
         set status = completed, completed_at = now, answer_text = answer
    else:
         keep status pending, store answer_text
```

**Compliance rollup (tasks)**
```
function task_rollup(company_id):
    ensure_assignments(company_id)
    for each task in scope:
         completed = count user_tasks status=completed
         total = count user_tasks
    compliance_pct = (count tasks where completed==total) / total tasks
```

**Compliance rollup (users)**
```
function user_rollup(company_id):
    for each user in scope:
         total = count assignments
         completed = count assignments status=completed
         overdue = count incomplete assignments with due_date < today
         status = Complete if pending==0 and overdue==0 else Pending/Overdue
    compliance_pct = users with status Complete / total users
```

## 5. Test plan (sample cases)
- Login success/fail: valid creds, invalid password, inactive user blocked.
- View tasks: user sees only assigned tasks; global + company-specific appear.
- Complete task: correct answer sets status=completed and timestamp; wrong answer stays pending.
- Overdue flag: task with past due_date shows overdue in dashboards.
- Compliance % (tasks): create 3 tasks, complete 2 fully → 66.6% shown on tiles/popups.
- Compliance % (users): 2 users, one with pending → 50% compliance.
- Global task propagation: add new company/user → global tasks auto-assigned; completed tasks not removed.
- CSV export: /admin/report/<user>/csv returns rows matching on-screen report.
- UI: company filter persists across dashboards; empty states show when no data.

## 6. Advanced features implemented
- Flask GUI with role-based navigation.
- SQLite persistence; password hashing.
- Charts (Chart.js) for severity/impact/completion; risk matrix.
- CSV export for reports.
- Overdue highlighting and compliance metrics.

## 7. Future improvement (if time)
- Optional JSON/CSV import/export mode to mirror the basic storage requirement.
- Email notifications for overdue tasks.
- Automated tests (pytest) for rollups and assignment sync.
