import os
import time 

def check_ping(hostname):
    
    response = os.system("ping -c 1 " + hostname + " > /dev/null 2>&1")
    
    # and then check the response...
    if response == 0:
        pingstatus = True
    else:
        pingstatus = False

    return pingstatus

def check_reachability(hostname, max_retry):

    count = 0
    while (count <= max_retry):

      ping = check_ping(hostname)
      if not ping:
          count += 1
      else:
          return True

    return False
