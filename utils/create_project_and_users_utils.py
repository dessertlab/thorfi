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

#Creating tenants
keystone.tenants.create(tenant_name="project_name1",
                        description="Default Tenant", enabled=True)

tenants = keystone.tenants.list()

#Creating users
my_tenant = [x for x in tenants if x.name=='project_name1'][0]
my_user = keystone.users.create(name="test1",
                                password="cardamom00",
                                tenant_id=my_tenant.id)

#Creating roles and adding users
#role = keystone.roles.create('role1')
#keystone.roles.add_user_role(my_user, role, my_tenant)


