#!/usr/bin/env python
"""Create a new admin user able to view the /reports endpoint."""
from getpass import getpass
import sys

from flask import current_app
from context import thorfi

from thorfi import app
from thorfi.models import User, db, Campaign

from werkzeug.security import generate_password_hash


def main():
    """Main entry point for script."""
    with app.app_context():
        db.metadata.create_all(db.engine)
        
        campaign = Campaign(campaign_name = 'pippo', user_username = 'admin')
        try:
          db.session.add(campaign)
          db.session.commit()
          print("campaign %s added" % campaign)
        except Exception as ex:
          print("Exception")

if __name__ == '__main__':
    sys.exit(main())
