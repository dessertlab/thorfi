"""Settings for Thor-FI installation."""

from os.path import abspath, dirname, join
import sys

if getattr(sys, "frozen", False):
    executable = sys.executable
else:
    executable = __file__


_cwd = dirname(abspath(executable))

AUTH_URL=''

# ThorFI CONFIGURATION
THORFI_INJECTOR_AGENT_DEFAULT_PORT='11223'
THORFI_OPENSTACK_IMAGE_NAME = 'thorfi_image'
THORFI_OPENSTACK_QCOW2_IMAGE_FILE = 'thorfi_image.qcow2'

THORFI_OPENSTACK_FLAVOR_NAME = 'thorfi_flavor'
THORFI_OPENSTACK_FLAVOR_VCPU = 4
THORFI_OPENSTACK_FLAVOR_RAM = 2048 #b
THORFI_OPENSTACK_FLAVOR_DISK = 3 #Gb

# Database URI for SQLAlchmey (Default: 'sqlite+pysqlite3:///sqlite3.db')
SQLALCHEMY_DATABASE_URI = 'sqlite:///'+ _cwd + '/thorfi_users.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Stripe secret key to be used to process purchases
STRIPE_SECRET_KEY = 'foo'

# Stripe public key to be used to process purchases
STRIPE_PUBLIC_KEY = 'bar'
