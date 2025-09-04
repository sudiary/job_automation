# routes.py
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory
from flask_login import login_required, current_user
from models import User, JobListing, Application
from sqlalchemy import select
from werkzeug.utils import secure_filename

ALLOWED_EXTS = {"pdf","docx","doc"}

def init_routes(app):
    main_bp = Blueprint("main", __name__)

    @main_bp.route("/")
    def index():
        session = current_app.db_session()
        stmt = select(JobListing).where(JobListing.status=="active")
        jobs = session.execute(stmt).scalars().all()
        session.close()
        return render_template("index.html", jobs=jobs)

    @main_bp.route("/dashboard")
    @login_required
    def dashboard():
        # load fresh user from DB
        session = current_app.db_session()
        user = session.get(User, int(current_user.id))
        session.close()
        return render_template("profile.html", user=user)

    @main_bp.route("/upload_profile_pic", methods=["POST"])
    @login_required
    def upload_profile_pic():
        file = request.files.get("profile_pic")
        if not file or file.filename=="":
            flash("Dosya seçilmedi", "danger")
            return redirect(url_for("main.dashboard"))
        ext = file.filename.rsplit(".",1)[-1].lower()
        if ext not in ALLOWED_EXTS and ext not in {"png","jpg","jpeg","gif"}:
            flash("İzin verilmeyen dosya türü", "danger")
            return redirect(url_for("main.dashboard"))
        filename = secure_filename(f"{current_user.id}_profile_{file.filename}")
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        file.save(path)
        session = current_app.db_session()
        u = session.get(User, int(current_user.id))
        u.profile_pic = filename
        session.commit()
        session.close()
        flash("Profil fotoğrafı yüklendi", "success")
        return redirect(url_for("main.dashboard"))

    @main_bp.route("/upload_cv", methods=["POST"])
    @login_required
    def upload_cv():
        file = request.files.get("cv")
        if not file or file.filename=="":
            flash("Dosya seçilmedi", "danger")
            return redirect(url_for("main.dashboard"))
        ext = file.filename.rsplit(".",1)[-1].lower()
        if ext not in ALLOWED_EXTS:
            flash("Sadece PDF veya DOCX yükleyin", "danger")
            return redirect(url_for("main.dashboard"))
        filename = secure_filename(f"{current_user.id}_cv_{file.filename}")
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        file.save(path)
        # optional: parse CV here (stub)
        session = current_app.db_session()
        u = session.get(User, int(current_user.id))
        u.cv_file = filename
        session.commit()
        session.close()
        flash("CV yüklendi", "success")
        return redirect(url_for("main.dashboard"))

    @main_bp.route("/uploads/<filename>")
    def uploaded_file(filename):
        return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)

    @main_bp.route("/change_password", methods=["POST"])
    @login_required
    def change_password():
        old = request.form.get("old_password","")
        new = request.form.get("new_password","")
        session = current_app.db_session()
        u = session.get(User, int(current_user.id))
        if not u.check_password(old):
            flash("Eski şifre hatalı", "danger")
            session.close()
            return redirect(url_for("main.dashboard"))
        u.set_password(new)
        session.commit()
        session.close()
        flash("Şifre değiştirildi", "success")
        return redirect(url_for("main.dashboard"))

    @main_bp.route("/delete_account", methods=["POST"])
    @login_required
    def delete_account():
        session = current_app.db_session()
        u = session.get(User, int(current_user.id))
        session.delete(u)
        session.commit()
        session.close()
        flash("Hesabınız silindi", "info")
        return redirect(url_for("auth.register"))

    # Admin panel
    @main_bp.route("/admin")
    @login_required
    def admin_panel():
        session = current_app.db_session()
        u = session.get(User, int(current_user.id))
        if not u.is_admin:
            session.close()
            flash("Yetersiz yetki", "danger")
            return redirect(url_for("main.dashboard"))
        users = session.execute(select(User)).scalars().all()
        session.close()
        return render_template("admin.html", users=users)

    # Jobs
    @main_bp.route("/jobs/create", methods=["GET","POST"])
    @login_required
    def create_job():
        # any registered user can create job in this simplified app; change as needed
        if request.method == "POST":
            company = request.form.get("company","").strip()
            position = request.form.get("position","").strip()
            description = request.form.get("description","").strip()
            tags = request.form.get("tags","").strip()
            session = current_app.db_session()
            j = JobListing(company=company, position=position, description=description, tags=tags)
            session.add(j); session.commit(); session.close()
            flash("İlan oluşturuldu", "success")
            return redirect(url_for("main.index"))
        return render_template("create_job.html")

    @main_bp.route("/job/<int:job_id>")
    def job_detail(job_id):
        session = current_app.db_session()
        j = session.get(JobListing, job_id)
        session.close()
        if not j:
            flash("İlan bulunamadı", "danger")
            return redirect(url_for("main.index"))
        return render_template("job_detail.html", job=j)

    @main_bp.route("/job/<int:job_id>/apply", methods=["POST"])
    @login_required
    def apply_job(job_id):
        session = current_app.db_session()
        existing = session.execute(select(Application).where(Application.job_id==job_id, Application.candidate_id==int(current_user.id))).scalars().first()
        if existing:
            flash("Zaten başvurdunuz", "info")
            session.close()
            return redirect(url_for("main.job_detail", job_id=job_id))
        approw = Application(job_id=job_id, candidate_id=int(current_user.id))
        session.add(approw); session.commit(); session.close()
        flash("Başvuru alındı", "success")
        return redirect(url_for("main.job_detail", job_id=job_id))

    app.register_blueprint(main_bp)
