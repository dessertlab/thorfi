import argparse
import sys
import glob
import os
from thorfi import app, db
from sqlalchemy import create_engine

def GetArgs():
    parser = argparse.ArgumentParser(description='Process args for retrieving arguments')
    parser.add_argument('-i', '--ip', required=True, action='store', help='Host IP on which injector agent is listening')
    parser.add_argument('-p', '--port', required=True, action='store', help='Host port on which injector agent is listening')
    parser.add_argument('-a', '--auth_url', required=False, default='http://localhost:5000/v3', action='store', help='Host port on which injector agent is listening')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Debug flag')
    args = parser.parse_args()
    return args

def get_app():
    """Return the application object."""
    return app

if __name__ == '__main__':
  
    if getattr(sys, "frozen", False):
        executable = sys.executable
    else:
        executable = __file__

    print "[thorfi_frontend_agent.py] executable", executable

    app.config.from_pyfile(os.path.join(os.path.dirname(os.path.abspath(executable)), 'config.py')) 
    
    #app.config.from_object('config')

    with app.app_context():
        engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], echo=True)
        db.metadata.create_all(engine)
  
    args = GetArgs()
    host_ip = args.ip
    host_port = args.port
    is_debug = args.debug
    is_threaded = True
    auth_url = args.auth_url
    
    app.config.update(AUTH_URL=auth_url) 

    # chmod 0400 on thorfi.key* files

    thorfi_agent_app_path = os.path.dirname(os.path.realpath(executable))

    for key_file in glob.glob(os.path.join(thorfi_agent_app_path, 'thorfi.key*')):
        st = os.stat(key_file)
        os.chmod(key_file, 0400)

    get_app().run(
                    host = host_ip,
                    port = int(host_port),
                    threaded = is_threaded,
                    debug = is_debug
                  )


