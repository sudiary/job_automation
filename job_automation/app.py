import os
import re
import json
import time
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime
from typing import Dict, Any, List, Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    g, send_from_directory, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ------- CONFIG -------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "ats_app.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_IMG = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_DOC = {"pdf", "doc", "docx"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# External job APIs (set via environment)
ADZUNA_APP_ID = os.getenv("ADZUNA_APP_ID", "")
ADZUNA_APP_KEY = os.getenv("ADZUNA_APP_KEY", "")
JOOBLE_KEY = os.getenv("JOOBLE_KEY", "")

# SMTP (optional; for email automation)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@example.com")

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = os.getenv("SECRET_KEY", "dev-change-this")


# ------- DB Helpers -------
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    c = db.cursor()

    # Users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'aday',
        profile_pic TEXT,
        cv_file TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Jobs
    c.execute("""
    CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        company TEXT,
        description TEXT,
        keywords TEXT,               -- virgülle ayrılmış anahtar kelimeler
        status TEXT NOT NULL DEFAULT 'aktif',  -- aktif/pasif
        employer_id INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(employer_id) REFERENCES users(id)
    )
    """)

    # Applications (fix: created_at sütunu var)
    c.execute("""
    CREATE TABLE IF NOT EXISTS applications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        user_id INTEGER,             -- kayıtlı kullanıcı başvurusu ise
        full_name TEXT,              -- misafir başvuru formu için
        email TEXT,
        platform TEXT,               -- linkedin/kariyer/indeed/email/site vb.
        cv_file TEXT,
        parsed_text TEXT,            -- raw parsed cv text
        skills TEXT,                 -- JSON list
        education TEXT,              -- kısa metin
        experience_years INTEGER,    -- tahmini yıl
        score INTEGER,               -- 0-100
        status TEXT DEFAULT 'beklemede',  -- uygun/uygun_degil/beklemede
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(job_id) REFERENCES jobs(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Messages (email logları için basit kayıt)
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id INTEGER,
        to_email TEXT,
        subject TEXT,
        body TEXT,
        transport TEXT, -- email/whatsapp
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(application_id) REFERENCES applications(id)
    )
    """)

    db.commit()



# ------- Utils -------
email_re = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
password_re = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$")

def allowed_file(filename: str, allowed: set) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed

def unique_name(prefix: str, filename: str) -> str:
    ts = int(time.time())
    sec = secure_filename(filename)
    return f"{ts}_{prefix}_{sec}"

def safe_int(x, default=0):
    try:
        return int(x)
    except:
        return default


# ------- CV Parsing -------
def parse_cv_to_text(file_path: str) -> str:
   
    ext = file_path.rsplit(".", 1)[-1].lower()
    text = ""
    try:
        if ext == "pdf":
            try:
                from pdfminer.high_level import extract_text
                text = extract_text(file_path) or ""
            except Exception:
                text = ""
        elif ext == "docx":
            try:
                import docx
                doc = docx.Document(file_path)
                text = "\n".join(p.text for p in doc.paragraphs)
            except Exception:
                text = ""
        elif ext == "doc":
            # Basit fallback; gerçek projede antiword vb. gerekir
            with open(file_path, "rb") as f:
                text = f.read().decode(errors="ignore")
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
    except Exception:
        text = ""
    return text.strip()


# ------- Field Extraction -------
SKILL_BANK = [
    "python","flask","django","fastapi","sql","postgresql","mysql",
    "docker","kubernetes","aws","gcp","azure","git","linux",
    "pandas","numpy","scikit-learn","javascript","react","node",
    "rest","graphql","redis","celery","rabbitmq","html","css"
]

def extract_fields_from_text(text: str) -> Dict[str, Any]:
    t = text.lower()
    skills = sorted({s for s in SKILL_BANK if s in t})
    # Deneyim yılı yakalama (örnek: "5 yıl", "3+ yıl")
    exp = 0
    for m in re.findall(r"(\d+)\s*\+?\s*(yil|yıl|year|yrs|y)", t):
        exp = max(exp, safe_int(m[0], 0))
    # Eğitim kaba tespiti
    education = None
    if any(k in t for k in ["master", "yüksek lisans", "msc"]):
        education = "Yüksek Lisans"
    elif any(k in t for k in ["lisans", "bachelor", "bsc"]):
        education = "Lisans"
    elif any(k in t for k in ["önlisans", "associate"]):
        education = "Önlisans"
    else:
        education = "Bilinmiyor"
    return {
        "skills": skills,
        "experience_years": exp,
        "education": education
    }


# ------- Scoring -------
def score_resume(cv_text: str, job_keywords: List[str]) -> int:
    """
    Çok basit anahtar kelime eşleştirme + deneyim ağırlığı.
    """
    t = cv_text.lower()
    matches = 0
    kw = [k.strip().lower() for k in job_keywords if k.strip()]
    for k in kw:
        if k in t:
            matches += 1
    if not kw:
        kw_score = 50
    else:
        kw_score = int(100 * (matches / max(1, len(kw))) * 0.8)

    fields = extract_fields_from_text(cv_text)
    exp_bonus = min(20, fields["experience_years"] * 3)  # max 20
    score = min(100, kw_score + exp_bonus)
    return int(score)


def decision_from_score(score: int) -> str:
    if score >= 70:
        return "uygun"
    if score >= 40:
        return "beklemede"
    return "uygun_degil"


# ------- Mail -------
def send_mail(to_email: str, subject: str, body: str) -> bool:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and to_email):
        # SMTP ayarlı değilse sessizce geç
        return False
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception:
        return False


# ------- Routes: Auth -------


@app.route('/application/<int:application_id>')
@login_required
def view_applicant_profile(application_id):
    
    application = Application.query.get_or_404(application_id)
    
    
    job = JobListing.query.get_or_404(application.job_id)
    if job.user_id != current_user.id:
        from flask import abort
        abort(403) # Forbidden
        
    
    applicant_user = User.query.get_or_404(application.user_id)
    
    
    return render_template('view_applicant_profile.html', 
                           application=application, 
                           job=job, 
                           applicant_user=applicant_user)



@app.route('/job/<int:job_id>/applicants')
@login_required
def view_applicants(job_id):
    # İlgili ilanı veritabanından bul.
    # Eğer ilan yoksa veya ilanın sahibi mevcut kullanıcı değilse 404 veya 403 hatası ver.
    job = JobListing.query.filter_by(id=job_id, user_id=current_user.id).first_or_404()

    applicants = Application.query.filter_by(job_id=job.id).order_by(Application.score.desc()).all()
    
    return render_template('view_applicants.html', job=job, applicants=applicants)

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        role = (request.form.get("role") or "aday").strip()

        if len(username) < 8:
            flash("Kullanıcı adı en az 8 karakter olmalı.", "danger")
            return redirect(url_for("register"))
        if not email_re.match(email):
            flash("Geçerli bir e-posta giriniz.", "danger")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Şifreler eşleşmiyor.", "danger")
            return redirect(url_for("register"))
        if not password_re.match(password):
            flash("Şifre: en az 8 karakter, büyük/küçük harf, rakam ve özel karakter içermeli.", "danger")
            return redirect(url_for("register"))
        if role not in ("aday", "işveren", "admin"):
            role = "aday"

        db = get_db()
        try:
            db.execute("""
                INSERT INTO users(username,email,password,role)
                VALUES(?,?,?,?)
            """, (username, email, generate_password_hash(password), role))
            db.commit()
            flash("Kayıt başarılı. Giriş yapabilirsiniz.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Kullanıcı adı veya e-posta zaten kayıtlı.", "danger")
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username=? OR email=? LIMIT 1", (identifier, identifier))
        user = cur.fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Giriş başarılı.", "success")
            return redirect(url_for("dashboard"))
        flash("Giriş bilgileri hatalı.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))


# ------- Routes: Dashboard -------
@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    db = get_db()
    cur = db.execute("SELECT * FROM jobs WHERE employer_id=? ORDER BY created_at DESC", (session["user_id"],))
    my_jobs = cur.fetchall()
    return render_template("dashboard.html", my_jobs=my_jobs)


# ------- Routes: Jobs -------
@app.route("/jobs/new", methods=["GET", "POST"])
def create_job():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        company = (request.form.get("company") or "").strip()
        keywords = (request.form.get("keywords") or "").strip()  # "python, flask, docker"
        status = request.form.get("status") or "aktif"
        if not title:
            flash("Başlık zorunlu.", "danger")
            return redirect(url_for("create_job"))
        db = get_db()
        db.execute("""
            INSERT INTO jobs(title,company,description,keywords,status,employer_id)
            VALUES(?,?,?,?,?,?)
        """, (title, company, description, keywords, status, session["user_id"]))
        db.commit()
        flash("İlan oluşturuldu.", "success")
        return redirect(url_for("dashboard"))
    return render_template("job_new.html")

@app.route("/jobs")
def list_jobs():
    db = get_db()
    cur = db.execute("SELECT * FROM jobs WHERE status='aktif' ORDER BY created_at DESC")
    jobs = cur.fetchall()
    return render_template("jobs.html", jobs=jobs)

@app.route("/jobs/<int:job_id>/status", methods=["POST"])
def toggle_job_status(job_id: int):
    if not session.get("user_id"):
        abort(403)
    status = (request.form.get("status") or "").strip()
    if status not in ("aktif", "pasif"):
        abort(400)
    db = get_db()
    # only owner can update
    db.execute("UPDATE jobs SET status=? WHERE id=? AND employer_id=?", (status, job_id, session["user_id"]))
    db.commit()
    flash("İlan durumu güncellendi.", "success")
    return redirect(url_for("dashboard"))


# ------- Routes: External Jobs (Adzuna / Jooble) -------
import requests

@app.route("/external-jobs")
def external_jobs():
    """
    /external-jobs?provider=adzuna&what=python&where=istanbul&country=tr
    /external-jobs?provider=jooble&keywords=python&location=istanbul
    """
    provider = (request.args.get("provider") or "adzuna").lower()
    result = {"provider": provider, "items": [], "note": ""}

    try:
        if provider == "adzuna":
            app_id, app_key = ADZUNA_APP_ID, ADZUNA_APP_KEY
            if not app_id or not app_key:
                result["note"] = "ADZUNA_APP_ID/ADZUNA_APP_KEY gerekli (env)."
                return jsonify(result)
            country = (request.args.get("country") or "tr").lower()
            what = request.args.get("what", "")
            where = request.args.get("where", "")
            page = int(request.args.get("page", "1"))
            url = f"https://api.adzuna.com/v1/api/jobs/{country}/search/{page}"
            params = {
                "app_id": app_id,
                "app_key": app_key,
                "what": what,
                "where": where,
                "results_per_page": 20,
                "content-type": "application/json"
            }
            r = requests.get(url, params=params, timeout=10)
            data = r.json()
            items = []
            for it in data.get("results", []):
                items.append({
                    "title": it.get("title"),
                    "company": (it.get("company") or {}).get("display_name"),
                    "location": (it.get("location") or {}).get("display_name"),
                    "url": it.get("redirect_url"),
                    "created": it.get("created")
                })
            result["items"] = items
            return jsonify(result)

        elif provider == "jooble":
            key = JOOBLE_KEY
            if not key:
                result["note"] = "JOOBLE_KEY gerekli (env)."
                return jsonify(result)
            url = f"https://jooble.org/api/{key}"
            payload = {
                "keywords": request.args.get("keywords", ""),
                "location": request.args.get("location", "")
            }
            r = requests.post(url, json=payload, timeout=10)
            data = r.json()
            items = []
            for it in data.get("jobs", []):
                items.append({
                    "title": it.get("title"),
                    "company": it.get("company"),
                    "location": it.get("location"),
                    "url": it.get("link"),
                    "created": it.get("updated")
                })
            result["items"] = items
            return jsonify(result)

        else:
            result["note"] = "Desteklenen provider: adzuna, jooble"
            return jsonify(result)

    except Exception as e:
        result["note"] = f"hata: {e}"
        return jsonify(result), 500


# ------- Routes: Apply / My Applications -------
@app.route("/jobs/<int:job_id>/apply", methods=["GET", "POST"])
def apply_job(job_id: int):
    db = get_db()
    c = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
    job = c.fetchone()
    if not job:
        abort(404)

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        platform = (request.form.get("platform") or "site").strip().lower()
        if not email_re.match(email):
            flash("Geçerli e-posta gerekli.", "danger")
            return redirect(url_for("apply_job", job_id=job_id))

        cvf = request.files.get("cv_file")
        cv_name = None
        if cvf and cvf.filename and allowed_file(cvf.filename, ALLOWED_DOC):
            cv_name = unique_name(full_name or session.get("username","anon"), cvf.filename)
            cvf.save(os.path.join(UPLOAD_DIR, cv_name))
        else:
            flash("CV yükleyiniz (pdf/doc/docx).", "danger")
            return redirect(url_for("apply_job", job_id=job_id))

        # Parse + fields + score
        parsed = parse_cv_to_text(os.path.join(UPLOAD_DIR, cv_name))
        fields = extract_fields_from_text(parsed)
        keywords = (job["keywords"] or "").split(",")
        sc = score_resume(parsed, keywords)
        decision = decision_from_score(sc)

        db.execute("""
            INSERT INTO applications(job_id, user_id, full_name, email, platform, cv_file,
                                     parsed_text, skills, education, experience_years, score, status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            job_id,
            session.get("user_id"),
            full_name,
            email,
            platform,
            cv_name,
            parsed,
            json.dumps(fields["skills"]),
            fields["education"],
            fields["experience_years"],
            sc,
            decision
        ))
        db.commit()

        # Optional: otomatik e-posta
        _ = send_mail(
            to_email=email,
            subject=f"{job['title']} başvurunuz alındı",
            body=f"Merhaba {full_name or ''},\n\nBaşvurunuz için teşekkürler. Puan: {sc}/100\n\nATS"
        )

        flash("Başvurunuz alındı.", "success")
        return redirect(url_for("list_jobs"))

    return render_template("apply.html", job=job)

@app.route("/my_applications")
def my_applications():
    if not session.get("user_id"):
        flash("Lütfen giriş yapın.", "warning")
        return redirect(url_for("login"))
    db = get_db()
    cur = db.execute("""
        SELECT a.id, a.created_at, a.score, a.status,
               j.title, j.company
        FROM applications a
        JOIN jobs j ON j.id = a.job_id
        WHERE a.user_id = ?
        ORDER BY a.created_at DESC
    """, (session["user_id"],))
    rows = cur.fetchall()
    return render_template("my_applications.html", applications=rows)


# ------- Routes: Messaging (email templates) -------
TEMPLATES = {
    "on_elemesi": "Merhaba {name}, ön değerlendirme tamamlandı. Süreci yakında paylaşacağız.",
    "mulakat": "Merhaba {name}, {date} tarihinde {time} saatinde mülakat davetimiz var.",
    "olumsuz": "Merhaba {name}, başvurun için teşekkürler. Bu pozisyon için ilerleyemiyoruz."
}

@app.route("/applications/<int:app_id>/message", methods=["POST"])
def send_message(app_id: int):
    if not session.get("user_id"):
        abort(403)
    db = get_db()
    cur = db.execute("SELECT * FROM applications WHERE id=?", (app_id,))
    application = cur.fetchone()
    if not application:
        abort(404)
    template_key = request.form.get("template") or "on_elemesi"
    subject = request.form.get("subject") or "Bilgilendirme"
    body = request.form.get("body") or TEMPLATES.get(template_key, "")
    # Format name if available
    body = body.replace("{name}", application["full_name"] or "Aday")

    ok = send_mail(application["email"], subject, body)
    db.execute("""
        INSERT INTO messages(application_id, to_email, subject, body, transport)
        VALUES(?,?,?,?,?)
    """, (app_id, application["email"], subject, body, "email"))
    db.commit()

    if ok:
        flash("E-posta gönderildi.", "success")
    else:
        flash("SMTP ayarsız veya gönderim hatası (loglandı).", "warning")
    return redirect(request.referrer or url_for("dashboard"))


# ------- Routes: Reports -------
@app.route("/reports")
def reports():
    db = get_db()
    # ilan başına başvuru sayısı
    by_job = db.execute("""
        SELECT j.id, j.title, COUNT(a.id) as apps
        FROM jobs j LEFT JOIN applications a ON a.job_id = j.id
        GROUP BY j.id
        ORDER BY apps DESC
    """).fetchall()
    # ortalama aday puanı
    avg_score = db.execute("""
        SELECT AVG(score) FROM applications WHERE score IS NOT NULL
    """).fetchone()[0]
    # platform bazında oranlar
    by_platform = db.execute("""
        SELECT platform, COUNT(*) as cnt
        FROM applications
        WHERE platform IS NOT NULL AND platform <> ''
        GROUP BY platform
        ORDER BY cnt DESC
    """).fetchall()

    data = {
        "jobs": [dict(r) for r in by_job],
        "average_score": round(avg_score or 0, 2),
        "platforms": [dict(r) for r in by_platform]
    }
    # JSON döndürelim; HTML rapor sayfasını ayrı şablonla gösterebiliriz
    return jsonify(data)


# ------- Static uploads -------
@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ------- Minimal pages (dummy templates fallback) -------
# Not: Gerçek şablonlar templates klasöründe olmalı. Burada yoksa basit mesaj gösterir.
@app.errorhandler(404)
def not_found(e):
    return "404 Not Found", 404

@app.route("/_ping")
def ping():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


def bootstrap():
    init_db()
    # admin kullanıcı yoksa oluştur
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE role='admin' LIMIT 1")
    admin = cur.fetchone()
    if not admin:
        db.execute("""
            INSERT INTO users(username,email,password,role)
            VALUES(?,?,?,?)
        """, (
            "admin",
            "admin@example.com",
            generate_password_hash("admin123"),
            "admin"
        ))
        db.commit()

if __name__ == "__main__":
    with app.app_context():
        bootstrap()
    app.run(debug=True, host="0.0.0.0", port=5000)
