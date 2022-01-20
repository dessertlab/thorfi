import os

from flask import Flask
from jinja2 import Environment, FileSystemLoader, ChoiceLoader, PackageLoader
import argparse

from thorfi import thorfi, login_manager
from models import db

from datetime import timedelta
import md5
import sys


if getattr(sys, "frozen", False):
    executable = sys.executable


else:
    executable = __file__
  

print "[thorfi/__init__.py]", executable

#app = Flask(__name__)
app = Flask(__name__)

if getattr(sys, "frozen", False):
    app.config.from_pyfile(os.path.join(os.path.dirname(os.path.abspath(executable)), 'config.py'))
else:
    app.config.from_object('config')


app.config['SECRET_KEY'] = 'foo'
app.config['WTF_CSRF_KEY'] = 'foo'


app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=14)

app.jinja_loader = ChoiceLoader([
    PackageLoader('thorfi'),
    ])

db.init_app(app)
login_manager.init_app(app)
app.register_blueprint(thorfi)

__version__ = '1.0'
