from thorfi_utils import get_credentials_from_sources, get_client

credentials = get_credentials_from_sources()


ks = get_client('keystone', credentials['auth_url'], credentials['username'], credentials['password'], credentials['project_name'], credentials['project_domain_id'], credentials['user_domain_id'])

#Creating project
ks.projects.create(name='project_test_1', 
		   domain='default',
		   description="Example Project",
		   enabled=True)

#Creating user
projects = ks.projects.list()
my_project = [x for x in projects if x.name=='project_test_1'][0]
my_user = ks.users.create(name='user_test_1',
			  password='cardamom00',
			  project=my_project)

#Granting role
users = ks.users.list()
my_user = [x for x in users if x.name=='user_test_1'][0]
roles = ks.roles.list()
my_role = [x for x in roles if x.name=="_member_"][0]
ks.roles.grant(role=my_role, user=my_user, project=my_project)
