import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change_for_prod")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///ats.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "app", "static", "uploads")
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024

    # SMTP (opsiyonel)
    SMTP_HOST = os.environ.get("SMTP_HOST")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER")
    SMTP_PASS = os.environ.get("SMTP_PASS")
    MAIL_FROM  = os.environ.get("MAIL_FROM", "noreply@example.com")

    APP_NAME = "ATS Talent Suite"
