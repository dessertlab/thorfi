#!/usr/bin/env python
"""Create a new admin user able to view the /reports endpoint."""
from getpass import getpass
import sys

from flask import current_app
from context import thorfi

from thorfi import app
from thorfi.models import User, db

from werkzeug.security import generate_password_hash

user1 = ('user_test_1','cardamom00','project_test_1','user_domain_name1','admin','default','default','81273981237','physical')
user2 = ('user_test_2','cardamom00','project_test_2','user_domain_name2','default','default','99999999','physical')
users_list = []
users_list.append(user1)
users_list.append(user2)

def main():
    """Main entry point for script."""
    with app.app_context():
        db.metadata.create_all(db.engine)
        
        for l in users_list:
            #print("Adding user %s pwd %s project_name %s project_domain_id %s user_domain_id %s" % (l[0], l[1], l[2], l[3], l[4]))
            user = User(username=l[0], 
                        password=l[1], 
                        project_name=l[2], 
                        user_domain_name=l[3], 
                        project_domain_id=l[4], 
                        user_domain_id=l[5],
                        project_id=l[6],
                        urole=l[7])
            print user
            db.session.add(user)
            db.session.commit()
            print("User %s added" % user)

if __name__ == '__main__':
    sys.exit(main())
