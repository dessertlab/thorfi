
"""Forms for the bull application."""
from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField, SelectField, BooleanField, StringField
from wtforms.validators import DataRequired, IPAddress, Email

from models import db

class LoginForm(FlaskForm):
  
    """Form class for user login."""
    username = TextField('OpenStack username', validators=[DataRequired()])
    password = PasswordField('OpenStack password', validators=[DataRequired()])
    user_domain_name = TextField('User Domain Name', default="Default", validators=[DataRequired()])

    project_name = TextField('OpenStack Project Name')
    project_domain_id = TextField('OpenStack Project Domain ID', default='default')
    user_domain_id = TextField('Openstack User Domain ID', default='default')

    project_id = TextField('OpenStack Project ID')

    usernamePhysical = TextField('Username')

    urole = TextField('URole', default='virtual')

    #auth_url_checkbox = BooleanField('Default', default=False)
    #auth_url = StringField('OpenStack Authentication URL', default="http://localhost:5000/v3", validators=[DataRequired()])

    
class RegisterForm(FlaskForm):

    ''' Form class for user registration. '''
    username = TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    project_name = TextField('OpenStack Project Name', validators=[DataRequired()])
    auth_url = TextField('Auth_URL', validators=[DataRequired()])
    project_domain_id = TextField('Project Domain ID', validators=[DataRequired()])
    user_domain_id = TextField('User Domain ID', validators=[DataRequired()])
