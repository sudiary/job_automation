from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Şifre", validators=[DataRequired()])
    submit = SubmitField("Giriş Yap")

class RegisterForm(FlaskForm):
    username = StringField("Kullanıcı Adı", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Şifre", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Kayıt Ol")

class JobForm(FlaskForm):
    title = StringField("İlan Başlığı", validators=[DataRequired()])
    description = TextAreaField("İlan Açıklaması", validators=[DataRequired()])
    company = StringField("Şirket Adı", validators=[DataRequired()])
    submit = SubmitField("İlanı Kaydet")

class CandidateForm(FlaskForm):
    name = StringField("Ad Soyad", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    cv_file = FileField("CV Yükle")
    submit = SubmitField("Adayı Kaydet")
