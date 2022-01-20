class ThorFIdbException(Exception):
     """An exception occurred during the ThorFI db operations"""

class ThorFIdbDuplicateCampaignException(ThorFIdbException):
    def __init__(self, username, new_campaign_name):
        print("The '%s' campaign for the user '%s' already exist" % (username, new_campaign_name))

