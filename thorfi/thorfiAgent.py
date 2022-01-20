import flask
import sys
import os

from flask import Flask

from utils.thorfi_utils import *

from thorfi_exceptions import ThorFIAuthException

class ThorFIAgent():

    def __init__(self, client_auth=None, nova_cli=None, neutron_cli=None, glance_cli=None, heat_cli=None, thorfi_app_dir=None, thorfi_root_dir=None, thorfi_log_file_name=None, logger=None, thorfi_workload=None, phy_network_topology=None):

        #self.client_auth = client_auth
        #self.neutron_cli = neutron_cli
        #self.nova_cli = nova_cli
        #self.glance_cli =  glance_cli
        #self.heat_cli = heat_cli
        self.thorfi_workload = thorfi_workload
        self.phy_network_topology = phy_network_topology

        if getattr(sys, "frozen", False):
            executable = sys.executable
            self.thorfi_app_dir = os.path.dirname(executable)
        else:
            executable = __file__
            self.thorfi_app_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(executable)), os.pardir))

        self.thorfi_root_dir = self.thorfi_app_dir + '/thorfi'

        self.thorfi_log_file_name = thorfi_log_file_name

        self.logger = logger

    def setClientAuth(self, client_auth):
        try:
          self.client_auth = client_auth
        except:
          exc_type, exc_value, exc_traceback = sys.exc_info()
          traceback.print_tb(exc_traceback, limit=10000, file=sys.stdout)
          raise ThorFIAuthException(client_auth['username'])

    def getClientAuth(self):
          return self.client_auth

    def getNeutronClientAuth(self):

        try:
              client_auth = self.getClientAuth()
              neutron_cli = get_client('neutron', 
                                                client_auth['auth_url'], 
                                                client_auth['username'],
                                                client_auth['password'],
                                                client_auth['project_name'],
                                                client_auth['project_domain_id'],
                                                client_auth['user_domain_id']
                                            )
              return neutron_cli
        except:
              exc_type, exc_value, exc_traceback = sys.exc_info()
              traceback.print_tb(exc_traceback, limit=10000, file=sys.stdout)
              raise ThorFIAuthException(client_auth['username'])

    def getNovaClientAuth(self):

        try:
              client_auth = self.getClientAuth()
              nova_cli = get_client('nova', 
                                                client_auth['auth_url'], 
                                                client_auth['username'],
                                                client_auth['password'],
                                                client_auth['project_name'],
                                                client_auth['project_domain_id'],
                                                client_auth['user_domain_id']
                                            )
              return nova_cli
        except:
              exc_type, exc_value, exc_traceback = sys.exc_info()
              traceback.print_tb(exc_traceback, limit=10000, file=sys.stdout)
              raise ThorFIAuthException(client_auth['username'])


    def getGlanceClientAuth(self):

        try:
              client_auth = self.getClientAuth()
              glance_cli = get_client('glance', 
                                                client_auth['auth_url'], 
                                                client_auth['username'],
                                                client_auth['password'],
                                                client_auth['project_name'],
                                                client_auth['project_domain_id'],
                                                client_auth['user_domain_id']
                                            )
              return glance_cli
        except:
              exc_type, exc_value, exc_traceback = sys.exc_info()
              traceback.print_tb(exc_traceback, limit=10000, file=sys.stdout)
              raise ThorFIAuthException(client_auth['username'])


    def getHeatClientAuth(self):

        try:
              client_auth = self.getClientAuth()
              heat_cli = get_client('heat', 
                                                client_auth['auth_url'], 
                                                client_auth['username'],
                                                client_auth['password'],
                                                client_auth['project_name'],
                                                client_auth['project_domain_id'],
                                                client_auth['user_domain_id']
                                            )
              return heat_cli
        except:
              exc_type, exc_value, exc_traceback = sys.exc_info()
              traceback.print_tb(exc_traceback, limit=10000, file=sys.stdout)
              raise ThorFIAuthException(client_auth['username'])


    def getThorFIappDirPath(self):
          return self.thorfi_app_dir

    def getThorFIrootDirPath(self):
          return self.thorfi_root_dir

    def setThorFILogFileName(self, thorfi_log_file_name):
          self.thorfi_log_file_name = thorfi_log_file_name

    def getThorFILogFileName(self):
          return self.thorfi_log_file_name

    def setThorFILogger(self, logger):
          self.logger = logger

    def getThorFILogger(self):
          return self.logger

    def setThorFIWorkloadRef(self, thorfi_workload):
          self.thorfi_workload = thorfi_workload

    def getThorFIWorkloadRef(self):
          return self.thorfi_workload

    def getPhyNetworkTopology(self):
          return self.phy_network_topology

    def setPhyNetworkTopology(self, phy_network_topology):
          self.phy_network_topology = phy_network_topology
  
