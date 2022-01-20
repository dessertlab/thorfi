from thorfi_utils import get_credentials_from_sources, get_client

credentials = get_credentials_from_sources()

ks = get_client('keystone', credentials['auth_url'], credentials['username'], credentials['password'], credentials['project_name'], credentials['project_domain_id'], credentials['user_domain_id'])

projects = ks.projects.list()
my_project = [x for x in projects if x.name=='project_test_1'][0]

users = ks.users.list()
my_user = [x for x in users if x.name=='user_test_1'][0]

#Deleting user
ks.users.delete(my_user)

#Deleting project
ks.projects.delete(my_project)
