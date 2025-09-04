from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

app = create_app()

@app.before_first_request
def ensure_admin_once():
    # Admin yoksa bir defa oluştur
    if not User.query.filter_by(role="admin").first():
        admin = User(
            username="admin",
            email="admin@example.com",
            role="admin",
            password_hash=generate_password_hash("Admin123!")
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)
