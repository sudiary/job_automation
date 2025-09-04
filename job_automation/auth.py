from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from .. import db
from ..models import User, PasswordResetToken
from werkzeug.security import generate_password_hash
from email_validator import validate_email, EmailNotValidError
import secrets, datetime as dt

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        role     = request.form.get("role","aday")
        try:
            validate_email(email)
        except EmailNotValidError:
            flash("Geçersiz e-posta", "danger"); return redirect(url_for("auth.register"))
        if role not in ["aday","işveren"]:
            role = "aday"
        if not username or not email or not password:
            flash("Lütfen tüm alanları doldurun", "danger"); return redirect(url_for("auth.register"))
        if User.query.filter((User.email==email)|(User.username==username)).first():
            flash("Kullanıcı adı veya e-posta kullanımda", "danger"); return redirect(url_for("auth.register"))
        u = User(username=username, email=email, role=role)
        u.set_password(password)
        db.session.add(u); db.session.commit()
        flash("Kayıt başarılı — giriş yapabilirsiniz", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")

@auth_bp.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        u = User.query.filter_by(email=email).first()
        if u and u.check_password(password):
            login_user(u)
            flash("Giriş başarılı", "success")
            return redirect(url_for("main.dashboard"))
        flash("E-posta veya şifre hatalı", "danger")
    return render_template("login.html")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Çıkış yapıldı", "info")
    return redirect(url_for("main.index"))

@auth_bp.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        u = User.query.filter_by(email=email).first()
        if not u:
            flash("Kullanıcı bulunamadı", "danger"); return redirect(url_for("auth.forgot"))
        token = secrets.token_urlsafe(32)
        pr = PasswordResetToken(user_id=u.id, token=token, 
                                expires_at=dt.datetime.utcnow()+dt.timedelta(hours=1))
        db.session.add(pr); db.session.commit()
        # prod: e-posta gönder; burada login sayfasında flash
        flash(f"Şifre sıfırlama bağlantısı: /reset/{token}", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot.html")

@auth_bp.route("/reset/<token>", methods=["GET","POST"])
def reset(token):
    pr = PasswordResetToken.query.filter_by(token=token).first()
    if not pr or pr.expires_at < dt.datetime.utcnow():
        flash("Token geçersiz veya süresi doldu", "danger"); return redirect(url_for("auth.forgot"))
    if request.method == "POST":
        new_pw = request.form.get("password","")
        if not new_pw:
            flash("Yeni şifre girin", "danger"); return redirect(url_for("auth.reset", token=token))
        u = User.query.get(pr.user_id)
        u.set_password(new_pw)
        db.session.delete(pr); db.session.commit()
        flash("Şifre güncellendi", "success")
        return redirect(url_for("auth.login"))
    return render_template("reset.html")
