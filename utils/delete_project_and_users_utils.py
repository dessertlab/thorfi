from keystoneauth1.identity import v2
from keystoneauth1 import session
from keystoneclient.v2_0 import client

username='admin'
password='admin'
tenant_name='admin'
auth_url='http://10.0.20.46:5000/v2.0'

auth = v2.Password(username=username, password=password,
                   tenant_name=tenant_name, auth_url=auth_url)
sess = session.Session(auth=auth)
keystone = client.Client(session=sess)

tenants = keystone.tenants.list()

my_tenant = [x for x in tenants if x.name=='project_name1'][0]

my_user = keystone.users.list(my_tenant.id)
#print my_user
keystone.users.delete(*my_user)
keystone.tenants.delete(my_tenant)
#print my_user
#my_role = keystone.roles.roles_for_user(my_user.id, my_tenant.id)
#roles = keystone.roles.list()
#print roles
