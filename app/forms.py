from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    TextAreaField, RadioField
from wtforms.fields.html5 import DateField  
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, \
    Length
from app.models import User


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class MeasureSetupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    individual_unit = RadioField('Unit of Measure', choices=[('Individuals', 'Individuals'), ('Encounters', 'Encounters')])
    start_date = DateField('Measurement Period Start Date', format='%Y-%m-%d')
    end_date = DateField('Measurement Period End Date', format='%Y-%m-%d')
    positive_direction = RadioField('Measure Directionality', choices=[('Positive', 'Positive'), ('Negative','Negative')])
    location = StringField('Location', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super(MeasureSetupForm, self).__init__(*args, **kwargs)
        self.original_username = original_username


class EditProfileForm(FlaskForm):
    '''
    The implementation is in a custom validation method, but there is an overloaded 
    constructor that accepts the original username as an argument. This username is 
    saved as an instance variable, and checked in the validate_username() method. If 
    the username entered in the form is the same as the original username, then there 
    is no reason to check the database for duplicates.

    To use this new validation method, I need to add the original username argument 
    in the view function, where the form object is created:
    '''
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')


class PostForm(FlaskForm):
    post = TextAreaField('Say something', validators=[DataRequired(), Length(min=1,max=140)])
    submit = SubmitField('Submit')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')