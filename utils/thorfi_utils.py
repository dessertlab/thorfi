import os, sys
import traceback

if getattr(sys, "frozen", False):
    executable = sys.executable
    print "executable:", executable

    openstack_lib_path = os.path.join(os.path.dirname(os.path.abspath(executable)), 'libs/')

    print "openstack lib path:", openstack_lib_path

    sys.path.append(openstack_lib_path)
    #sys.path.append("/usr/lib/python2.7/site-packages/")

else:
    executable = __file__


try:

    from keystoneauth1 import identity
    from keystoneauth1 import session

    from neutronclient.v2_0 import client as neutron_client
    from novaclient import client as nova_client
    from keystoneclient.v3 import client as keystone_client
    from glanceclient import client as glance_client
    from heatclient import client as heat_client

except:
    print("WARNING! Some OpenStack libraries are not installed! You can perform only injection tests on physical network topology.")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=None, file=sys.stdout)

from thorfi_utils_exceptions import ThorFIUtilsGetClientException


def get_client(openstack_component, auth_url, username, password, project_name, project_domain_id, user_domain_id):
    """
        Return a client using a session authentication method. 
            :param str openstack_component: openstack service	(i.e. keystone, neutron, nova, glance, heat)
            :param str auth_url: url of the identity service 	(i.e. http://localhost:5000/v3)
            :param str username: username 			(i.e. admin)
            :param str password: password 			(i.e. admin)
            :param str project_name: project name 		(i.e. admin)
            :param str project_domain_id: project domain id 	(i.e. default)   
            :param str user_domain_id: user domain id or name 	(i.e. default)     
    """

    cli = None
    
    try:
        auth = identity.Password(auth_url=auth_url,
                                  username=username,
                                  password=password,
                                  project_name=project_name,
                                  project_domain_id=project_domain_id,
                                  user_domain_id=user_domain_id)


        sess = session.Session(auth=auth)


        if 'neutron' in openstack_component:
            cli = neutron_client.Client(session=sess)
            cli.get_auth_info()

        elif 'nova' in openstack_component:
            cli = nova_client.Client(2, session=sess)

        elif 'keystone' in openstack_component:
            cli = keystone_client.Client(session=sess)

        elif 'glance' in openstack_component:
            cli = glance_client.Client('2', session=sess)
      
        elif 'heat' in openstack_component:
            cli = heat_client.Client('1', session=sess)


    except:
        raise ThorFIUtilsGetClientException

    return cli
    

def get_credentials_from_sources():

    try:

        d = {}
        d['username'] = os.environ['OS_USERNAME']
        d['password'] = os.environ['OS_PASSWORD']
        d['auth_url'] = os.environ['OS_AUTH_URL']
        d['project_name'] = os.environ['OS_PROJECT_NAME']

        # workaround to convert Default into default string
        # by default, keystone db the default domain 'Default' is saved as 'default'

        user_domain_id = os.environ['OS_USER_DOMAIN_NAME']
        project_domain_id = os.environ['OS_PROJECT_DOMAIN_NAME']

        if 'Default' in user_domain_id:
            user_domain_id = user_domain_id.lower()

        if 'Default' in project_domain_id:
            project_domain_id = project_domain_id.lower()

        d['user_domain_id'] = user_domain_id
        d['user_domain_name'] = user_domain_id
        d['project_domain_id'] = project_domain_id


    except KeyError as e:
        print(e)
        print("Missing Openstack credentials to run ThorFI injector...Please source credential file before")
        sys.exit(1)

    return d


def print_values(val, type):
    if type == 'ports':
        val_list = val['ports']
    if type == 'networks':
        val_list = val['networks']
    if type == 'routers':
        val_list = val['routers']
    for p in val_list:
        for k, v in p.items():
            print("%s : %s" % (k, v))
        print('\n')


def print_values_server(val, server_id, type):
    if type == 'ports':
        val_list = val['ports']

    if type == 'networks':
        val_list = val['networks']
    for p in val_list:
        bool = False
        for k, v in p.items():
            if k == 'device_id' and v == server_id:
                bool = True
        if bool:
            for k, v in p.items():
                print("%s : %s" % (k, v))
            print('\n')
