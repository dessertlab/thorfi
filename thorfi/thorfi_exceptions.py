class ThorFIException(Exception):
    """An exception occurred during the ThorFI workflow"""


class ThorFINetworkNotFoundException(ThorFIException):

    def __init__(self, resource_name):
        print("Network resource '%s' does not exists" % resource_name)

class ThorFISubnetNotFoundException(ThorFIException):

    def __init__(self, resource_name):
        print("Subnet resource '%s' does not exists" % resource_name)


class ThorFIRouterNotFoundException(ThorFIException):

    def __init__(self, resource_name):
        print("Router resource '%s' does not exists" % resource_name)

class ThorFIPortNotFoundException(ThorFIException):

    def __init__(self, resource_name):
        print("Port resource '%s' does not exists" % resource_name)

class ThorFIDeviceOwnerNotSupported(ThorFIException):

    def __init__(self, device_owner):
        print("Device owner '%s' is not yet supported for injection" % device_owner)

class ThorFIFloatingIPException(ThorFIException):

    def __init__(self, target_fip):
        print("Floating IP '%s' does not exist or is in 'DOWN' state" % target_fip)


class ThorFIAuthException(ThorFIException):

    def __init__(self, username):
        print("Openstack user '%s' does not exist or password is wrong" % username)

class ThorFIStackCreationException(ThorFIException):

    def __init__(self, thorfi_stack_name):
        print("Error during creation of stack named '%s'" % thorfi_stack_name)

class ThorFIStackUpdateException(ThorFIException):

    def __init__(self, thorfi_stack_name):
        print("Error during update of stack named '%s'" % thorfi_stack_name)

class ThorFIStackDeletionException(ThorFIException):

    def __init__(self, thorfi_stack_name):
        print("Error during deletion of stack named '%s'" % thorfi_stack_name)

class NoInjectorAgentsException(ThorFIException):

    def __init__(self):
        print("No injector agents are reachable from ThorFI master agent!")

