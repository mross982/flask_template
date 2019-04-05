from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    TextAreaField, RadioField, DecimalField, FieldList, IntegerField, FormField, \
    FloatField
from wtforms.fields.html5 import DateField 
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, \
    Length, NumberRange, Optional
from app.models import User, Benchmark
from werkzeug.datastructures import MultiDict
import config


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


class BenchmarksSubForm(FlaskForm):
    benchmark = FloatField('Performance Rate', validators=[Optional()], filters=[lambda x: x or None])
    value = FloatField('Value          $', validators=[Optional()],filters=[lambda x: x or None])


class MeasureSetupForm(FlaskForm):
    # username = StringField('Username', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    unit = RadioField('Unit of Measure', choices=[('Individuals', 'Individuals'), ('Encounters', 'Encounters')], validators=[DataRequired()])
    start_date = DateField('Measurement Period Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('Measurement Period End Date', format='%Y-%m-%d', validators=[DataRequired()])
    direction = RadioField('Measure Directionality', choices=[('Positive', 'Positive'), ('Negative','Negative')], validators=[DataRequired()])
    # benchmarks = FieldList(FormField(BenchmarksSubForm), min_entries=config.benchmark_entry_fields)
    # submit = SubmitField('Complete')


class BenchmarksForm(FlaskForm):
    # add FieldList to combine multiple instances of the same field
    benchmarks = FieldList(FormField(BenchmarksSubForm), min_entries=config.benchmark_entry_fields)
    submit = SubmitField('Submit')

    def populate_form(measure_id):
        benchmarks = Benchmark.query.filter_by(measure_id=measure_id).all()
        benchmark_form = BenchmarksForm()
        while len(benchmark_form.benchmarks) > 0:
            benchmark_form.benchmarks.pop_entry()
        for benchmark in benchmarks:
            b_data = dict()
            b_data['benchmark'] = benchmark.benchmark
            b_data['value'] = benchmark.value
            benchmark_form.benchmarks.append_entry(b_data)

        # add blank fields to min number:
        while len(benchmark_form.benchmarks) < 6:
            b_data = dict()
            b_data['benchmark'] = ''
            b_data['value'] = ''
            benchmark_form.benchmarks.append_entry(b_data)
        
        return benchmark_form

class WarningForm(FlaskForm ):
    delete = SubmitField('Delete Measure')
    save = SubmitField('Return')








#**************** Extra Code ***************************************


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