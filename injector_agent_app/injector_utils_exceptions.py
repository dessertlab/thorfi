class ThorFIUtilsException(Exception):
    """An exception occurred using the ThorFI utils lib"""


class ThorFIUtilsGetClientException(ThorFIUtilsException):

    def __init__(self, resource_name):
        print("ThorFI authentication errors! Please check your credentials in openstack.")


