import flask
import argparse
import time
import requests
import uuid
import json
import traceback
import werkzeug
import shutil
import copy
import csv
import subprocess
#import pickle
import cPickle as pickle
import hashlib
import ast
import re

#from nocache import nocache

from network_utils import get_local_nics
from functools import wraps
from urlparse import urlparse, urljoin

from flask import Flask, jsonify, request, url_for

from flask import (Blueprint, send_from_directory, abort, request,
                   render_template, current_app, redirect, url_for)


from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, login_user, logout_user, current_user

from multiprocessing import Pool

import multiprocessing as mp

import sys, os


if getattr(sys, "frozen", False):

    executable = sys.executable
    
    print executable

    openstack_lib_path = os.path.join(os.path.dirname(os.path.abspath(executable)), 'libs/')

    sys.path.append(openstack_lib_path)

else:
    executable = __file__


try:
    from keystoneauth1 import identity
    from keystoneauth1 import session

    from neutronclient.v2_0 import client

except:
    print("WARNING!!! Some OpenStack client libraries cannot be imported. You can perform only injection test on physical network topology!")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=None, file=sys.stdout)
    pass

from utils.thorfi_utils import *
from utils.thorfi_ssh_util import *
from utils.thorfi_ping_utils import *
from utils.thorfi_json_utils import *

from utils.thorfi_db_utils import *
from utils.thorfi_db_utils_exceptions import *

from thorfi_exceptions import *

from thorfiAgent import ThorFIAgent

from thorfi_image_manager import *

from thorfi_workload import *

import logging

from models import *
from forms import LoginForm, RegisterForm

from time import sleep


# Global variables

thorfi = Blueprint('thorfi', __name__)

login_manager = LoginManager()

phy_network_topology = {}
phy_network_map = {}
switches_list = []
switches_port_list = {}

logger_list = {}

host_down = None

def getObjectRef(pickled_object_ref):
    return pickle.loads(pickled_object_ref.encode('utf-8'))    

def flush_thorfi_log(thorfiAgent):

  if thorfiAgent:
      thorfi_log_file = thorfiAgent.getThorFILogFileName()

      if thorfi_log_file:
          #flush thorfi log file
          open(thorfi_log_file, 'w').close()


def create_thorfi_app_logger(thorfiAgent, cur_user, thorfi_log_file):
   
    global logger_list 

    # create separate app logger and log to file 'thorfi_log_file'

    if cur_user in logger_list:
        logger = logger_list[cur_user]
    else:
    #if thorfiAgent:
    #    logger = thorfiAgent.getThorFILogger()

        #logger = logging.getLogger(__name__)
        logger = logging.getLogger(cur_user)

        print("CREATE LOGGER for user: %s (obj ref: %s)" % (cur_user, logger))

        # push to root logger also debug log from app
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(process)d thorfi ' + cur_user + ' %(levelname)s %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(thorfi_log_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        logger_list[cur_user] = logger

    return logger


def get_thorfi_app_logger(thorfiAgent):

    try:

        thorfi_path = thorfiAgent.getThorFIrootDirPath() + '/'
      

        cur_user = current_user.user_signature

        thorfi_log_file = thorfi_path + cur_user + '_thorfi.log'  
        
        #flush thorfi log file
        # open(thorfi_log_file, 'w').close()

        thorfiAgent.setThorFILogFileName(thorfi_log_file)
        refreshed_agent_ref = pickle.dumps(thorfiAgent)
        update_user_agent_ref(current_user.user_signature, refreshed_agent_ref)

        logger = create_thorfi_app_logger(thorfiAgent, cur_user, thorfi_log_file)

        return logger

    except AttributeError as ex:

        print ("Anonymus user...go on...")

@login_manager.user_loader
def load_user(user_id):
    """Given *user_id*, return the associated User object.

    :param unicode user_id: user_id (username) user to retrieve

    """
    return User.query.filter_by(username=user_id).first()

def update_user_agent_ref(user_signature, agent_ref):

    user = User.query.filter_by(user_signature=user_signature).first()
    
    user.agent_ref = agent_ref.encode('utf-8')

    try:
        db.session.commit()
    except:
        pass


def check_host_status(host_id_list):
            
    hosts_status = {}

    default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']
    not_alive = 0

    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    for host in host_id_list:

        try:
            logger.debug("Send alive request to inject at %s" % (host))

            req_to_inject = requests.get('http://' + host + ':' + default_injector_port + '/alive', hooks=dict(response=print_response))

            hosts_status[host] = 'up'

        except requests.exceptions.ConnectionError as e:

            hosts_status[host] = 'down'
            not_alive += 1

    if not_alive == len(host_id_list):
        raise NoInjectorAgentsException() 
    else:
        host_down = []
        for host, status in hosts_status.items():
          if status in 'down':
              logger.warning("Impossible to reach injector agent on node: %s status: %s" % (host, status))
              host_down.append(host)

        return host_down

def check_injector_agents_virtual(neutron_client):

    thorfiAgent = getObjectRef(current_user.agent_ref)  
  
    logger = get_thorfi_app_logger(thorfiAgent)

    host_id_list = []


    #get list of ports and the relative 'binding:host_id'
    for port in neutron_client.list_ports()['ports']:

        if 'binding:host_id' in port:
            curr_host_id = port['binding:host_id']
            if curr_host_id and curr_host_id not in host_id_list:
                host_id_list.append(curr_host_id)

    logger.info("list of binding:host_id ===> %s" % host_id_list)
 
    if host_id_list:
        return check_host_status(host_id_list)
       
def check_injector_agents_physical():

    thorfiAgent = getObjectRef(current_user.agent_ref)  
  
    logger = get_thorfi_app_logger(thorfiAgent)

    host_id_list = []

    #get info about target host machine after deploy
    thorfi_workload_ref = thorfiAgent.getThorFIWorkloadRef()

    if thorfi_workload_ref:
        thorfi_wl_param = thorfi_workload_ref.getThorFIWorkloadParams()

        workload_type = thorfi_workload_ref.getThorFIWorkloadType()
        if workload_type in 'iperf':
          
            iperf_client_ip = thorfi_wl_param['iperf_client_ip']
            iperf_server_ip = thorfi_wl_param['iperf_server_ip']
        
            host_id_list.append(iperf_client_ip)            
            host_id_list.append(iperf_server_ip)            
    
        logger.info("list of phy host ip ===> %s" % host_id_list)

    if host_id_list:
        return check_host_status(host_id_list)




@thorfi.route("/check_agents", methods=["GET"])
def check_agents():
    
    global host_down

    thorfiAgent = getObjectRef(current_user.agent_ref)

    try:
        
        if 'virtual' in current_user.urole:
            host_down = check_injector_agents_virtual(thorfiAgent.getNeutronClientAuth())
        else:
            host_down = check_injector_agents_physical()

        if host_down:
            
            return json.dumps(host_down)

        return "OK"

    except NoInjectorAgentsException as ex:
        return "all_down"

import gc
def do_logout():
    
    """Logout the current user."""

    global phy_network_topology
    global logger_list

    print ("Logout user: %s" % current_user.user_signature)
    thorfiAgent = getObjectRef(current_user.agent_ref)
    flush_thorfi_log(thorfiAgent)
 
    user = User.query.filter_by(user_signature=current_user.user_signature).first()
    db.session.delete(user)
    db.session.commit()
 
    phy_network_topology = {}
    phy_network_map = {}
    switches_list = []
    switches_port_list = {}

    #remove logger ref from 'logger_list'
    del logger_list[current_user.user_signature]


    logout_user()

    # activate garbage collection
    gc.collect()

@thorfi.route("/logout", methods=["GET", "POST"])
@login_required
def logout():

    do_logout() 

    return "OK"


@thorfi.route("/get_auth_url", methods=["GET"])
def get_auth_url():

    return json.dumps(current_app.config['AUTH_URL'])

@thorfi.route("/projectList", methods=["POST"])
def projectList():


  username = request.form["username"]
  password = request.form["password"]
  user_domain_name = request.form["user_domain_name"]
  #auth_url = request.form["auth_url"]
  auth_url = current_app.config['AUTH_URL']

  try:
    auth = identity.v3.Password( auth_url=auth_url,
                        username=username,
                        password=password,
                        user_domain_name=user_domain_name)

    sess = session.Session(auth=auth)
    cli = keystone_client.Client(session=session)

    headers = {
      'X-Auth-Token': sess.get_token(),
      'Content-type': 'application/json',
    }

    response = requests.get(auth_url + '/auth/projects', headers=headers)

    resp = json.loads(response.content)

    return json.dumps(resp)

  except:
    print("Authentication failed - Invalid OpenStack credentials")
    abort (401)



@thorfi.route("/createCampaign", methods=["POST"])
def createCampaign():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  new_campaign_name = request.form['campaign_name']

  try:
    setCampaignFromUser(current_user.user_signature, new_campaign_name)
    
    logger.debug("Create new campaign '%s' for user '%s'" % (current_user.user_signature, new_campaign_name))

    return "OK"

  except ThorFIdbDuplicateCampaignException as exc:
    abort (502)

  except Exception as ex:
    logger.error("Exceptions during createCampaign!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort (501)
  

@thorfi.route("/getCampaignList", methods=['GET'])
def getCampaignList():
  
  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  try:
    
    logger.debug("Get campaign_list for user '%s'" % current_user.user_signature)

    campaign_list = getCampaignListFromUser(current_user.user_signature)

  except Exception as e:

    abort (501)

  return json.dumps(campaign_list)


@thorfi.route("/loadCampaign", methods=["POST"])
def loadCampaign():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  campaign_name = request.form['campaign']

  try:
    campaign_id = getCampaignID(current_user.user_signature, campaign_name)

    fips_list = getTestsFromCampaign(campaign_id)

    return json.dumps(fips_list)

  except Exception as ex:
    logger.error("Exceptions during createCampaign!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort (501)


@thorfi.route("/saveWorkloadConfiguration", methods=["POST"])
def saveWorkloadConfiguration():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)
  
  campaign_name = request.form['campaign_name']
  workload_type = request.form['workload_type']
  iperf_client_nodes = request.form['iperf_client_nodes']
  iperf_client_link = request.form['iperf_client_link']
  iperf_server_nodes = request.form['iperf_server_nodes']
  iperf_server_link = request.form['iperf_server_link']
  jmeter_client_nodes = request.form['jmeter_client_nodes']
  jmeter_client_link = request.form['jmeter_client_link']

  try:

    campaign_id = getCampaignID(current_user.user_signature, campaign_name)

    wl_conf = {}
    wl_conf['workload_type'] = workload_type
    if workload_type == "jmeter":
      wl_conf['iperf_client_generator_conf'] = str({'nodes' : {} , 'links' : {} })
      wl_conf['iperf_server_generator_conf'] = str({'nodes' : {} , 'links' : {} })
      wl_conf['jmeter_client_generator_conf'] = str({'nodes' : jmeter_client_nodes , 'links' : jmeter_client_link })
    else:
      wl_conf['iperf_client_generator_conf'] = str({'nodes' : iperf_client_nodes , 'links' : iperf_client_link })
      wl_conf['iperf_server_generator_conf'] = str({'nodes' : iperf_server_nodes , 'links' : iperf_server_link })
      wl_conf['jmeter_client_generator_conf'] = str({'nodes' : {} , 'links' : {} })

    setWL_Conf(campaign_id, wl_conf)

    return "OK"

  except Exception as ex:
    logger.error("Exceptions during createCampaign!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort (501)


@thorfi.route("/get_network_topology", methods=["POST"])
@login_required
def get_network_topology():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  try:

      print("Start scan for visual network topology")

      thorfi_instances_name = ["__ThorFI_iperf_client", "__ThorFI_iperf_server", "__ThorFI_jmeter_client"]

      resp = networkslist()
      networks_list = json.loads(resp)

      resp = routerslist()
      routers_list = json.loads(resp)

      resp = serverslist()
      servers_list = json.loads(resp)

      #remove thorfi_instances vm
      new_list_servers = {}
      new_list_servers['servers'] = []

      for element in servers_list['servers']:
        if not element['name'] in thorfi_instances_name:
          new_list_servers['servers'].append(element)

      servers_list = new_list_servers

      resp = portslist()
      ports_list = json.loads(resp)

      #remove *iperf_server_port* and *iperf_client_port* and *jmeter_client_port*
      new_list_ports = {}
      new_list_ports['ports'] = []

      #save id of filtered ports. This information is used to filter floating ip
      new_list_ports_id = []

      for element in ports_list['ports']:
        if not "iperf_server_port" in element['name'] and not "iperf_client_port" in element['name'] and not "jmeter_client_port" in element['name']:
          new_list_ports['ports'].append(element)
          new_list_ports_id.append(element['id'])

      ports_list = new_list_ports

      resp = subnetslist()
      subnets_list = json.loads(resp)

      resp = floatingipslist()
      floatingips_list = json.loads(resp)

      #remove thorfi instances floating Ips
      new_list_floating_ips = {}
      new_list_ports['floatingips'] = []
      
      for element in floatingips_list['floatingips']:
        if not element['port_id'] in new_list_ports_id:
          new_list_ports['floatingips'].append(element)

      floatingips_list = new_list_floating_ips  


      groups =  { "public": 1,
                  "router": 2,
                  "net": 3,
                  "subnet": 4,
                  "server": 5,
                  "loadBalancer": 6
                }

      network_topology = {}
      network_topology['nodes'] = []
      network_topology['links'] = []

      for network in networks_list['networks']:
        node = {}
        node['name'] = str(network['name'])
        node['type'] = "resource"
        node['ID'] = network['id']
        if network['router:external']:
          #public networks
          node['group'] = groups["public"]
        else:
          node['group'] = groups["net"]

        node['fault_target'] = str(network['name'])
        
        network_topology['nodes'].append(node)

      for router in routers_list['routers']:

        device_id = router['id']

        node = {}
        node['name'] = str(router['name'])
        node['type'] = "resource"
        node['group'] = groups['router']
        node['fault_target'] = []
        node['ID'] = router['id']

        #add port network:router_gateway to router in the network topology
        #these ports are filtering by neutron_cli.list_ports(project_id=current_user.project_id) because the relative project_id is null.
        #get neutron clien
        thorfiAgent = getObjectRef(current_user.agent_ref)
        neutron_cli = thorfiAgent.getNeutronClientAuth()
        #get list of ports
        ports = neutron_cli.list_ports(device_owner="network:router_gateway")

        for port in ports['ports']:
          if port['fixed_ips'][0]['ip_address'] == router['external_gateway_info']['external_fixed_ips'][0]['ip_address']:
            sub_node = {}
            sub_node['subtarget'] = "port"
            sub_node['value'] = port['id']
            sub_node['name'] = port['fixed_ips'][0]['ip_address']
            
            node['fault_target'].append(sub_node)

        #add port network:router_interface to router in the network topology
        thorfiAgent = getObjectRef(current_user.agent_ref)
        neutron_cli = thorfiAgent.getNeutronClientAuth()

        ports = neutron_cli.list_ports(project_id=current_user.project_id)
        for port in ports_list['ports']:
          if port['device_owner'] == "network:router_interface" and port['device_id'] == device_id:
            sub_node = {}
            sub_node['subtarget'] = "port"
            sub_node['value'] = port['id']
            sub_node['name'] = port['fixed_ips'][0]['ip_address']
            
            node['fault_target'].append(sub_node)

        network_topology['nodes'].append(node)

      for subnet in subnets_list['subnets']:
        node = {}
        node['name'] = str(subnet['name'])
        node['type'] = "resource"
        node['group'] = groups["subnet"]
        node['fault_target'] = str(subnet['name'])
        node['ID'] = subnet['id']

        network_topology['nodes'].append(node)

      for server in servers_list['servers']:

        device_id = server['id']

        node = {}
        node['name'] = str(server['name'])
        node['type'] = "resource"
        node['group'] = groups['server']
        node['fault_target'] = []
        node['ID'] = server['id']

        addresses = server['addresses']
        #add floatingip to vm node in the network topology
        for address in addresses:
          interfaces = addresses[address]
          for interface in interfaces:
            if interface['OS-EXT-IPS:type'] == "floating":
              sub_node = {}
              sub_node['subtarget'] = "floatingip"
              sub_node['value'] = interface['addr']
              sub_node['name'] = interface['addr']
              
              node['fault_target'].append(sub_node)

        #add list of ports to vm node in the network topology
        for port in ports_list['ports']:
          if port['device_owner'] == "compute:nova" and port['device_id'] == device_id:
            sub_node = {}
            sub_node['subtarget'] = "port"
            sub_node['value'] = port['id']
            sub_node['name'] = port['fixed_ips'][0]['ip_address']

            node['fault_target'].append(sub_node)

        network_topology['nodes'].append(node)


      #dict of {network_id:network_name}
      networkID_dict = {}
      for network in networks_list['networks']:
        networkID_dict.update({network['id']:network['name']})

      #dict of {router_id:router_name}
      routerID_dict = {}
      for router in routers_list['routers']:
        routerID_dict.update({router['id']:router['name']})

      #dict of {server_id:server_name}
      serverID_dict = {}
      for server in servers_list['servers']:
        serverID_dict.update({server['id']:server['name']})

      #dict of {subnet_id:subnet_name}
      subnetID_dict = {}
      for subnet in subnets_list['subnets']:
        subnetID_dict.update({subnet['id']:subnet['name']})


      #create links between routers and public networks
      for router in routers_list['routers']:
        link = {}

        router_name = router['name']
        router_id = router['id']
        network_id = router['external_gateway_info']['network_id']
        network_name = networkID_dict[network_id]

        link['source'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == network_id), None)
        link['target'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == router_id), None)
        link['value'] = 1
        link['distance'] = 70


        network_topology['links'].append(link)

      #create links between subnets and networks
      for subnet in subnets_list['subnets']:
        link = {}

        subnet_id = subnet['id']
        subnet_name = subnet['name']
        network_id = subnet['network_id']
        network_name = networkID_dict[network_id]

        link['source'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == network_id), None)
        link['target'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == subnet_id), None)
        
        link['value'] = 1
        link['distance'] = 70

        network_topology['links'].append(link)    

      #create links between:  
      # - routers and non-public networks
      # - subnets and virtual machines 
      for port in ports_list['ports']:   

        # - routers and non-public networks
        if port['device_owner'] == "network:router_interface":

          link = {}
        
          network_id = port['network_id']
          network_name = networkID_dict[network_id]
          router_id = port['device_id']
          router_name = routerID_dict[router_id]

          #link['source'] is source_id in nodes list 
          link['source'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == router_id), None)
          #link['target'] is target_id in nodes list 
          link['target'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == network_id), None)
          #link['value'] is the weight of link
          link['value'] = 1
          link['distance'] = 70

          network_topology['links'].append(link)
        
        # - subnets and virtual machines 
        if port['device_owner'] == "compute:nova":

          link = {} 

          subnet_id = port['fixed_ips'][0]['subnet_id']
          subnet_name = subnetID_dict[subnet_id]
          server_id = port['device_id']
          server_name = serverID_dict[server_id]
        
          link['source'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == subnet_id), None)    
          link['target'] = next((index for (index, d) in enumerate(network_topology['nodes']) if d['ID'] == server_id), None)
          link['value'] = 1
          link['distance'] = 70
          
          network_topology['links'].append(link)


      #check if the network topology is changed
      campaign_name = request.form['campaign_name']
  
      campaign_id = getCampaignID(current_user.user_signature, campaign_name)

      db_network_topology_hash = getNet_Topology(campaign_id)

      network_topology_id_list = []
      for elem in network_topology['nodes']:
        network_topology_id_list.append(str(elem['ID']))
        if isinstance(elem['fault_target'], list):
            for elem_child in elem['fault_target']:
              network_topology_id_list.append(str(elem_child['value']))


      network_topology_id_list_sorted = sorted(network_topology_id_list)

      network_topology_id = ""

      for elem in network_topology_id_list_sorted:
        network_topology_id += elem

      scan_network_topology_hash = hashlib.sha1(network_topology_id).hexdigest()

      if db_network_topology_hash == "None":
        #set db_network_topology_hash 
        setNet_Topology(campaign_id=campaign_id, net_topology_hash=scan_network_topology_hash)
        return json.dumps(network_topology)

      else:
        if db_network_topology_hash == scan_network_topology_hash:
          return json.dumps(network_topology)
        else:
          raise ValueError('Network topology is changed!')

  except ValueError as err:
    logger.error("Exceptions scan virtual topology: %s !" %err)
    abort (403)

  except Exception as ex:
    logger.error("Exceptions scan virtual topology!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort (501)



@thorfi.route("/getPredefiniteWorkloadGenerators", methods=['POST'])
def getPredefiniteWorkloadGenerators():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  campaign_name = request.form['campaign_name']

  try: 

    campaign_id = getCampaignID(current_user.user_signature, campaign_name)

    wl_conf = getWL_Conf(campaign_id)

  except Exception as ex:
    logger.error("Exceptions during createCampaign!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort (501)

  iperf_client_num = 1
  iperf_server_num = 1
  jmeter_client_num = 1

  predefinite_workload_generators = {}
  predefinite_workload_generators['nodes'] = []
  predefinite_workload_generators['links'] = []


  new_node_base = {}
  new_node_base['group'] = 6
  new_node_base['type'] = "vm-workload"
  new_node_base['attached'] = "false"

  new_node_base['args'] = {}

  # set node structures properly (virtual or physical mode)
  if current_user.urole == "virtual":
    new_node_base['args']['net_ID'] = ""
    new_node_base['args']['net_group'] = ""
    new_node_base['args']['net_name'] = ""
    new_node_base['args']['subnet_ID'] = ""
    new_node_base['args']['subnet_name'] = ""
  else:
    new_node_base['args']['node_ip'] = "" 

  if ( wl_conf and wl_conf['workload_type'] == 'iperf' ):
    iperf_client_conf = ast.literal_eval(wl_conf['iperf_client_generator_conf'])
    iperf_client_conf_nodes = ast.literal_eval(iperf_client_conf['nodes'])
    iperf_client_conf_links = ast.literal_eval(iperf_client_conf['links'])

    new_node = {}
    new_node = copy.deepcopy(new_node_base)
    new_node['name'] = iperf_client_conf_nodes['name']
    new_node['args'] = iperf_client_conf_nodes['args']
    new_node['attached'] = iperf_client_conf_nodes['attached']

    new_link = {}
    new_link['distance'] = iperf_client_conf_links['distance']
    new_link['source'] = iperf_client_conf_links['source']
    new_link['target'] = iperf_client_conf_links['target']
    new_link['value'] = iperf_client_conf_links['value']

    predefinite_workload_generators['nodes'].append(new_node)
    predefinite_workload_generators['links'].append(new_link)

  else:
    for index in range(0, iperf_client_num):
      new_node = copy.deepcopy(new_node_base)       
      new_node['name'] = "iperf client"
      new_node['args']['bandwidth'] = "5"    
      new_node['args']['protocol'] = "tcp"
      predefinite_workload_generators['nodes'].append(new_node)


  if ( wl_conf and wl_conf['workload_type'] == 'iperf' ):
    iperf_server_conf = ast.literal_eval(wl_conf['iperf_server_generator_conf'])
    iperf_server_conf_nodes = ast.literal_eval(iperf_server_conf['nodes'])
    iperf_server_conf_links = ast.literal_eval(iperf_server_conf['links'])

    new_node = {}
    new_node = copy.deepcopy(new_node_base)
    new_node['name'] = iperf_server_conf_nodes['name']
    new_node['args'] = iperf_server_conf_nodes['args']
    new_node['attached'] = iperf_server_conf_nodes['attached']

    new_link = {}
    new_link['distance'] = iperf_server_conf_links['distance']
    new_link['source'] = iperf_server_conf_links['source']
    new_link['target'] = iperf_server_conf_links['target']
    new_link['value'] = iperf_server_conf_links['value']

    predefinite_workload_generators['nodes'].append(new_node)
    predefinite_workload_generators['links'].append(new_link)

  else:
    for index in range(0, iperf_server_num):
      new_node = {}
      new_node = copy.deepcopy(new_node_base)
      new_node['name'] = "iperf server"
      new_node['args']['server_port'] = "8080"
      predefinite_workload_generators['nodes'].append(new_node)


  if ( wl_conf and wl_conf['workload_type'] == 'jmeter' ):
    jmeter_conf = ast.literal_eval(wl_conf['jmeter_client_generator_conf'])
    jmeter_conf_nodes = ast.literal_eval(jmeter_conf['nodes'])
    jmeter_conf_links = ast.literal_eval(jmeter_conf['links'])

    new_node = {}
    new_node = copy.deepcopy(new_node_base)
    new_node['name'] = jmeter_conf_nodes['name']
    new_node['args'] = jmeter_conf_nodes['args']
    new_node['attached'] = jmeter_conf_nodes['attached']

    new_link = {}
    new_link['distance'] = jmeter_conf_links['distance']
    new_link['source'] = jmeter_conf_links['source']
    new_link['target'] = jmeter_conf_links['target']
    new_link['value'] = jmeter_conf_links['value']

    predefinite_workload_generators['nodes'].append(new_node)
    predefinite_workload_generators['links'].append(new_link)

  else:  

    for index in range(0, jmeter_client_num):
      new_node = {}
      new_node = copy.deepcopy(new_node_base)
      new_node['name'] = "jmeter client"
      new_node['args']['server_ip'] = "localhost"
      new_node['args']['server_port'] = "80"
      new_node['args']['requestMethod'] = "GET"
      new_node['args']['requestPage'] = "index.html"
      new_node['args']['requestThroughput'] = "600"
      new_node['args']['connect_timeout'] = ""
      new_node['args']['response_timeout'] = ""

      predefinite_workload_generators['nodes'].append(new_node)

  return json.dumps(predefinite_workload_generators)


def get_host_nics():

      local_nics = get_local_nics()
      return local_nics

def start_physical_scan(phy_host_ip_list, logger, default_injector_port):
    
    pool = mp.Pool()
    for host_ip_address in phy_host_ip_list:    

        logger.debug("Start thread for scanning host: %s" % host_ip_address)
        pool.apply_async(physical_scan_worker, args = (host_ip_address, default_injector_port,), callback = update_physical_scan_info)
         
    pool.close()
    pool.join()


def update_physical_scan_info(result):

    global phy_network_map
    global switches_list
    global switches_port_list

    if result:
        host_nics = result[0]
        l2_info = result[1]
        local_switches_list = result[2]
        local_switches_port_list = result[3]
        host_ip_address = result[4]

        # update 'phy_network_map'
        phy_network_map[host_ip_address] = {'nics': host_nics, 'l2_info': l2_info}

        # update 'switches_list'
        for el in local_switches_list:
            if el not in switches_list:
                switches_list.append(el)

        # update 'switches_port_list'
        for key, value in local_switches_port_list.items():
            switches_port_list.setdefault(key, []).append(value)
   
    else:
    
      return


def physical_scan_worker(host_ip_address, default_injector_port):

    l2_info = {}
    local_switches_list = []
    local_switches_port_list = {}
   
    
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)


    try:
        logger.debug("Send request at %s" % (host_ip_address))

        req_to_inject = requests.get('http://' + host_ip_address + ':' + default_injector_port + '/get_host_nics', hooks=dict(response=print_response))
        
        host_nics = json.loads(req_to_inject.text)
        del host_nics['lo'] 
      
        # get L2 info through get_l2_info API

        for nic_name in host_nics:

            logger.debug("Request to %s for NIC: %s" % (host_ip_address, nic_name))
                
            req_to_inject = requests.post('http://' + host_ip_address + ':' + default_injector_port + '/get_l2_info', json={'nic':nic_name}, hooks=dict(response=print_response))
            l2_info_list = json.loads(req_to_inject.text)

            l2_info[nic_name] = l2_info_list

            switch_id = l2_info_list['device_id']
            switch_port_id = l2_info_list['port_id']
            switch_address = l2_info_list['addresses']

            logger.debug("Switch ID: %s PORT_ID %s ADDRESS %s" % (switch_id, switch_port_id, switch_address))
            logger.debug("nic_name: %s host_ip_address: %s" % (nic_name, host_ip_address))

            local_switches_port_list.setdefault(switch_port_id, []).append({switch_id: {host_ip_address : nic_name}})
            
            if switch_id not in local_switches_list:
                local_switches_list.append(switch_id)
        
        return (host_nics, l2_info, local_switches_list, local_switches_port_list, host_ip_address)


    except requests.exceptions.ConnectionError as e:
        
        logger.debug("Impossible to reach injector agent on node: %s...skip it" % host_ip_address)
        return None

@thorfi.route("/scanPhyNetworkTopology", methods=["POST"])
#@login_required
def scanPhyNetworkTopology():

    global phy_network_map
    global switches_list
    global switches_port_list
    global phy_network_topology

    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    thorfi_app_dir = thorfiAgent.getThorFIappDirPath() + '/'
    thorfi_networktools_path = thorfi_app_dir + '/network_tools/'

    if any(phy_network_topology):
        logger.info("Found a previous physical topology...")
        #return json.dumps(phy_network_topology)

    else:
      logger.info("Not found a previous physical topology...")
      
      phy_network_topology['nodes'] = []
      phy_network_topology['links'] = []

      # Get list of all host up IPs by current host (the node on which we start thorfi agent):
      # E.g.: nmap -v -sP 10.0.20.0/24|grep -v down|grep "Nmap scan report for" 

      local_nics = get_host_nics()
      del local_nics['lo']

      logger.info("ThorFI agent local nics: %s" % local_nics)

      # list of phy host IP addresses
      phy_host_ip_list = []

      #for each phy nic get a network map
      for nic_name, ip_address in local_nics.items():

          host_ip_list = []
          # Get L3 (host ip) info
    
          #get base address
          base_address = ip_address.split('.')
          base_address.pop()
          base_address.append('0')
          base_address = '.'.join(base_address)
          logger.info("Base address for %s %s is %s" % (nic_name, ip_address, base_address) )

          # execute nmap according to base_address
          nmap_command = thorfi_networktools_path + '/nmap -v -sP ' + base_address + '/24 |grep -v down |grep "Nmap scan report for"|awk \'{print $5}\''
          logger.debug("nmap command: %s" % nmap_command)
          process = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
          out, err = process.communicate()

          nmap_host_ip_list = out.strip().split('\n')
          host_ip_list = [el for el in nmap_host_ip_list if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", el)]

          logger.debug("Physical host list for nic %s: %s" % (nic_name, host_ip_list))

          phy_host_ip_list.extend(host_ip_list)


      logger.debug("Total list for hosts is: %s" %  phy_host_ip_list)
      logger.debug("START SCAN!")
    
      # for each host in 'phy_host_ip_list' send GET request to injector agent to know nics list and L2 info
      default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']
    
      start_physical_scan(phy_host_ip_list, logger, default_injector_port)

      groups =  { 
                  "server": 8,
                  "switch": 7
                }

      # creating host server nodes

      for host_ip, info in phy_network_map.items():

          node = {}
        
          for key, value in info.items():
            
            # the node is a server. we populate the subtarget with nic name and related ip address
            if 'nics' in key:
            
                node['name'] = host_ip
                node['type'] = "resource"
                node['group'] = groups['server']
                node['fault_target'] = []
                node['ID'] = host_ip
               
                for nic_name, ip_addr in value.items():
                  
                    sub_node = {}
                    sub_node['subtarget'] = "interface"
                    sub_node['value'] = ip_addr
                    sub_node['name'] = nic_name

                    node['fault_target'].append(sub_node)
                  
          phy_network_topology['nodes'].append(node)

      #creating switches nodes

      for switch_id in switches_list:
          node = {}
          node['name'] = switch_id
          node['type'] = "resource"
          node['group'] = groups['switch']
          node['fault_target'] = []
          node['fault_target_advanced'] = []
          node['ID'] = switch_id
          phy_network_topology['nodes'].append(node) 

      for switch_port, info in switches_port_list.items():
          el = {}
          for port_info in info:
              #get switch id
              for switch_id, host_info in port_info[0].items():
                  for node in phy_network_topology['nodes']:
                      if node['ID'] in switch_id:
                          el.setdefault(switch_port, []).append(host_info)
                          node['fault_target_advanced'] = el
  

      # create list of switches node
      switch_nodes = []
      for node in phy_network_topology['nodes']:

          if node['group'] == groups['switch']:

              for k, v in node['fault_target_advanced'].items():
                subnode = {}
                subnode['subtarget'] = "switch_port"
                subnode['value'] = k
                subnode['name'] = k
                node['fault_target'].append(subnode)

              switch_nodes.append(node)

      # creating links between server and switches

      for node in phy_network_topology['nodes']:

          if node['group'] == groups['server']:
            
              current_node_id = node['ID']

              #search for link with switches
              for switch in switch_nodes:
                  for switch_port_id, info in switch['fault_target_advanced'].items():
                      for host_nic in info:            
                          for ip, nic_name in host_nic.items():
                                
                              if current_node_id in ip:

                                  link = {}
                                  link['source'] = next((index for (index, d) in enumerate(phy_network_topology['nodes']) if d['ID'] == current_node_id), None)
                                  link['target'] = next((index for (index, d) in enumerate(phy_network_topology['nodes']) if d['ID'] == switch['ID']), None)

                                  link['value'] = 1
                                  link['distance'] = 70
                                
                                  phy_network_topology['links'].append(link)
 

      print("NETWORK TOPOLOGY: %s" % phy_network_topology)

    try:
      #check if the network topology is changed
      campaign_name = request.form['campaign_name']

      campaign_id = getCampaignID(current_user.user_signature, campaign_name)

      db_network_topology_hash = getNet_Topology(campaign_id)

      network_topology_id_list = []
      for elem in phy_network_topology['nodes']:
        network_topology_id_list.append(str(elem['ID']))
        if isinstance(elem['fault_target'], list):
            for elem_child in elem['fault_target']:
              network_topology_id_list.append(str(elem_child['value']))
      

      network_topology_id_list_sorted = sorted(network_topology_id_list)

      network_topology_id = ""

      for elem in network_topology_id_list_sorted:
        network_topology_id += elem

      scan_network_topology_hash = hashlib.sha1(network_topology_id).hexdigest()

      if db_network_topology_hash == "None":
        #set db_network_topology_hash 
        setNet_Topology(campaign_id=campaign_id, net_topology_hash=scan_network_topology_hash)
        return json.dumps(phy_network_topology)

      else:
        if db_network_topology_hash == scan_network_topology_hash:
          return json.dumps(phy_network_topology)
        else:
          raise ValueError('Network topology is changed!')

    except ValueError as err:
      logger.error("Exceptions scan physical topology: %s !" %err)
      abort (403)


@thorfi.route("/scanProjectPhysical", methods=["GET"])
@login_required
def scanProjectPhysical():

  global phy_network_topology
  sleep(3)
  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  #phy_network_topology = thorfiAgent.getPhyNetworkTopology()

  resources = []
  res = {}
  res['title'] = "infrastructure-resources"
  res['folder'] = "true"
  res['children'] = []

  #append to an array all physical resources 
  res_array = []
  for node in phy_network_topology['nodes']:

    res_map = {}
    if node['group'] == 7:
      res_map['title'] = "switch"
    elif node['group'] == 8:
      res_map['title'] = "node"

    res_map['name'] = node['name']
    res_map['id'] = node['ID']
    res_array.append(res_map)

    for subnode in node['fault_target']:
      res_map = {}
      res_map['title'] = subnode['subtarget']
      res_map['name'] = subnode['name']
      res_map['id'] = subnode['value']
      res_array.append(res_map)

  #extract all physical resource type (i.e. swirch, switch_port, node, interface)
  res_title_array = []
  for res_ in res_array:
    if not res_['title'] in res_title_array:
      res_title_array.append(res_['title'])

  #json compatible with fancytree javascript
  for res_title in res_title_array:
    a = {}
    a['title'] = res_title
    a['folder'] = "true"
    a['children'] = []
    for resource in res_array:
      if resource['title'] == res_title:
        b = {}
        b['title'] = resource['name']
        b['id'] = resource['id']
        a['children'].append(b)

    res['children'].append(a)

  resources.append(res)

  print("###### %s" %json.dumps(resources))

  return json.dumps(resources)


@thorfi.route("/scanProject", methods=["GET"])
@login_required
def scanProject():
    
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    logger.info("scanProject API call for user %s" % current_user.user_signature)

    #TODO: we may use multiprocessing pool
    resp = networkslist()
    networks = json.loads(resp)
    logger.info("Scanning Networks Completed.")

    resp = portslist()
    ports = json.loads(resp)
    logger.info("Scanning Ports Completed.")

    resp = routerslist()
    routers = json.loads(resp)
    logger.info("Scanning Routers Completed.")

    resp = floatingipslist()
    floatingips = json.loads(resp)
    logger.info("Scanning FloatingIPs Completed.")

    resp = subnetslist()
    subnets = json.loads(resp)
    logger.info("Scanning Subnets Completed.")
 
    resources = []
    res = {}
    res['title'] = "tenant-resources"
    res['folder'] = "true"
    res['children'] = []

    #this function is used to parse objResource to a json compatible with fancytree javascript  
    def parseScan(typeOfRes): 
        a = {}
        for k, v in typeOfRes.items(): 
        #if typeOfRes(i.e. networks, routers, etc...) is not empty
          if v:
            if k in ("networks","subnets","routers","ports","floatingips"):
              #remove "s" => "networks" => "network"
              k = k[:-1]
            a['title'] = k
            a['folder'] = "true"
            a['children'] = []
            #in resource we have a list of dict
            for resource in v:
              #is resource is a dict
              if isinstance(resource, dict):
                b={}
                if k == "floatingip":
                  b['title'] = resource['floating_ip_address']
                else:  
                  if resource['name']:
                    b['title'] = resource['name']
                  else:
                    #b['title'] = '(' + resource['id'][0:13] + ')'
                    b['title'] = resource['fixed_ips'][0]['ip_address']
                b['id'] = resource['id']
                a['children'].append(b)
            res['children'].append(a)
    resources.append(res)
             
    parseScan(networks)

    #remove *iperf_server_port* and *iperf_client_port* and *jmeter_client_port*
    new_list_ports = {}
    new_list_ports['ports'] = []

    #save id of filtered ports. This information is used to filter floating ip
    new_list_ports_id = []

    for element in ports['ports']:
      if not "iperf_server_port" in element['name'] and not "iperf_client_port" in element['name'] and not "jmeter_client_port" in element['name']:
        new_list_ports['ports'].append(element)
        new_list_ports_id.append(element['id'])

    ports = new_list_ports
    parseScan(ports)

    parseScan(routers)

    #remove thorfi instances floating Ips
    new_list_floating_ips = {}
    new_list_floating_ips['floatingips'] = []
    
    for element in floatingips['floatingips']:
      if element['port_id'] in new_list_ports_id:

        new_list_floating_ips['floatingips'].append(element)
        

    floatingips = new_list_floating_ips
    parseScan(floatingips)

    parseScan(subnets)

    logger.info("Scanning Project Completed !!!")
    logger.debug("Scan results: %s" % json.dumps(resources))

    print("######### %s" %resources)

    return json.dumps(resources)



@thorfi.route("/getFaultLibrary", methods=["GET"])
def getFaultLibrary():
  
  thorfiAgent = getObjectRef(current_user.agent_ref)

  thorfi_path = thorfiAgent.getThorFIrootDirPath() + '/'
  default_fault_library_file = thorfi_path + 'ThorFI_fault_library.json'
  try:  
    with open(default_fault_library_file, 'r') as file:
  
      fault_library = json.loads(file.read())

      resp = []
      if current_user.urole == "virtual":
        resp.append(fault_library[0])
        
      elif current_user.urole == "physical":
        resp.append(fault_library[1])

      return json.dumps(resp)
      

  except IOError as e:
    abort(404)
  except Exception as err:
    abort (501)


@thorfi.route("/getProgressStatus", methods=["POST"])
def getProgressStatus():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  thorfi_path = thorfiAgent.getThorFIrootDirPath() + '/'

  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  with open(campaign_path + '/fips_status.txt', 'r') as f:
    fip_status = f.readlines()

  progress_status = 0
  total_test = len(fip_status)
  completed_test = 0

  for line in fip_status:
    status = line.strip('\n').split('#')[1]
    if (status == "error" or status == "completed" or status == "skipped"):
      completed_test += 1

  try:
    progress_status = format( ((completed_test / (total_test * 1.0)) * 100) , '.1f');
  except ZeroDivisionError as error:
    abort(501)

  return json.dumps( {'progress' : progress_status} )


@thorfi.route("/getInfoTest", methods=["POST"])
def getInfoTest():
  
  thorfiAgent = getObjectRef(current_user.agent_ref)

  test_id = int(request.form["id_test"]);

  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  with open(campaign_path + '/fips_list.txt', 'r') as f:
    fip_info = f.readlines()[test_id-1]

  return json.dumps(fip_info)

@thorfi.route("/fastConfiguration", methods=["POST"])
def fastConfiguration():

  """
      API for adding new faults to data_network_topology data structure.
      For each resorce-type with 'selected=true' (i.e. network, subnet, etc..), compute all possible combinations with 
      corrisponded "component" and "fault-id" ('selected=true') defined in the fault library.  

      POST data:
            data_network_topology: is the current data structure used to build the network topology,
                                    that contains resource and fault nodes
            fault_library: is the fault library with selected faults, json "fancytree-compatible" 
            resources: is the list of resources scanned with selected specific resources, json "fancytree-compatible"
      Raises:
            #TODO:
  """
  
  fault_library = request.form["fault_library"]
  resources = request.form["resources"]

  fl = json.loads(str(fault_library))
  rs = json.loads(str(resources))
  
  #loop on selected resources
  res_selected = []
  for domain_rs in rs:
    domain_key = ''
    for key, value in domain_rs.items():
      domain_key = domain_rs['title']
      if isinstance(value,list):
        for component_rs in value:
          component_key = ''
          for key, value in component_rs.items():
            component_key = component_rs['title'] 
            if isinstance(value, list):
              for res_rs in value:
                for key, value in res_rs.items():
                  if key == "selected" and value == True:
                    res_name = res_rs['title']
                    res_id = res_rs['id']
                    #if component_rs['title'] == "port":
                    #  res_target = res_rs['id']
                    #else:
                    #  res_target = res_rs['title']
                    #res_target = res_rs['id']
                    res_selected.append([domain_key, component_key, res_name, res_id])

  #print ("***************************************")
  #print res_selected
  #print ("***************************************")
  #loop on selected faults
  fault_selected = []
  for domain_fl in fl:
    domain_key = ''
    for key, value in domain_fl.items():
      domain_key = domain_fl['title']
      if isinstance(value, list):
        for component_fl in value:
          component_key = ''
          for key, value in component_fl.items():
            component_key = component_fl['title']
            if isinstance(value, list):
              for fault_fl in value:
                for key, value in fault_fl.items():
                  if key == "selected" and value == True:
                    fault_key = fault_fl['title']
                    fault_args = fault_fl['args']
                    fault_description = fault_fl['description']
                    fault_selected.append([domain_key, component_key, fault_key, fault_args, fault_description])
  #print fault_selected

  #######################
  fips = []
  #fips['data'] = [] 

  for index in range(len(res_selected)):
    for index2 in range(len(fault_selected)):
      if (res_selected[index][0][:-10] == fault_selected[index2][0][:-7] and res_selected[index][1] == fault_selected[index2][1]):
        #fip = {}
        fip = []
        fip.append('')
        #domain [:-7] transforms "tenant-faults" in "tenant"
        #fip['domain'] = fault_selected[index2][0]
        fip.append(fault_selected[index2][0][:-7])
        #component
        #fip['component'] = res_selected[index][0]
        fip.append(res_selected[index][1])
        #name of resource
        #fip['target_resource'] = res_selected[index][1]
        fip.append(res_selected[index][2])
        #target of injector (i.e. network => name , port => ID, floatingip => IP)
        fip.append(res_selected[index][3])
        #type of fault
        #fip['fault_tipe'] = fault_selected[index2][2]
        fip.append(fault_selected[index2][2])
        #arg
        #fip['arg'] = fault_selected[index2][3]
        fip.append(fault_selected[index2][3])
        #description
        #fip['description'] = fault_selected[index2][4]
        fip.append(fault_selected[index2][4])
        #resurce id
        fip.append(res_selected[index][3])
        fips.append(fip)

  #print fips

  groups =  { "public": 1,
              "router": 2,
              "net": 3,
              "subnet": 4,
              "server": 5,
              "loadBalancer": 6,
              "latency" : 10,
              "loss" : 11,
              "corrupt" : 12,
              "delete" : 13,
              "duplicate" : 14,
              "bottleneck" : 15,
              "down" : 16,
              "reboot" : 17
            }
  '''
      fault node structure:
        new_node = {};
        new_node['group']                                                                     : [10..13] for type fault
        new_node['name']                                                                      : fault name
        new_node['type'] = "fault"                                                            : node type                                                    
        new_node['fault_target'] = {}                                                         : sub structure with fault param
        new_node['fault_target']['resource_type']                                             : component 
        new_node['fault_target']['resource_name']                                             : resource name 
        new_node['fault_target']['resource_faultID']                                          : target ID 
        new_node['args']                                                                      : fault arg
        new_node['description']                                                               : fault description
        new_link = {}
        new_link['source']                                                                    : resource index 
        new_link['target'] = data_network_topology['nodes']["length"]                         : fault index (i.e. length node array )
        new_link['value'] = 0                                                                 : link stroke-width value
        new_link['distance'] = 20;                                                            : link length 
  '''
  nodes = json.loads(request.form['nodes'])
  links = json.loads(request.form['links'])

  resp = {}
  resp['nodes'] = []
  resp['links'] = []

  if current_user.urole == "virtual":
    #get list of ports and floating ip
    #get neutron client 

    thorfiAgent = getObjectRef(current_user.agent_ref)
    neutron_cli = thorfiAgent.getNeutronClientAuth()

    #get list of networks
    ports_list = neutron_cli.list_ports()
    floatingips_list = neutron_cli.list_floatingips()

  list_of_faults = []
  list_of_faults = [ d for d in nodes if d['type'] == "fault"]

  i = 0;
  for fip in fips:
    new_node = {}
    new_node['group'] = groups[fip[5]]
    new_node['name'] = fip[5]
    new_node['type'] = "fault"
    new_node['fault_target'] = {}
    new_node['fault_target']['resource_type'] = fip[2]
    new_node['fault_target']['resource_name'] = fip[3]
    new_node['fault_target']['resource_faultID'] = fip[4]
    new_node['args'] = fip[6]
    new_node['description'] = fip[7]

    new_node['fault_pattern'] = {}
    new_node['fault_pattern']['name'] = "persistent"
    new_node['fault_pattern']['args'] = {}
    new_node['fault_pattern']['args']['arg1'] = ""
    new_node['fault_pattern']['args']['arg2'] = ""

    new_node['fault_target_traffic'] = {}
    new_node['fault_target_traffic']['name'] = "any traffic"
    new_node['fault_target_traffic']['args'] = {}
    new_node['fault_target_traffic']['args']['protocol'] = ""
    new_node['fault_target_traffic']['args']['src_ports'] = ""
    new_node['fault_target_traffic']['args']['dst_ports'] = ""
    new_node['status'] = "NotCompleted"
    
    new_link = {}
    
    new_link['target'] = len(nodes) + i;
    new_link['value'] = 0
    new_link['distance'] = 20

    if current_user.urole == "virtual":
      res_id = 0
      if new_node['fault_target']['resource_type'] == "port":
        #TODO: get correspondent owner (vm or router)
        res_id = [ d for d in ports_list['ports'] if d['id'] == new_node['fault_target']['resource_faultID'] ][0]['device_id']

      elif new_node['fault_target']['resource_type'] == "floatingip":
        #TODO: get correspondent owner (vm)
        port_id = [ d for d in floatingips_list['floatingips'] if d['floating_ip_address'] == new_node['fault_target']['resource_name'] ][0]['port_id']
        res_id = [ d for d in ports_list['ports'] if d['id'] == port_id ][0]['device_id']
      else:
        #TODO: get correspondent resource net, subnet, router.
        res_id = fip[8]

      new_link['source'] = [ d for d in nodes if d['type'] == "resource" and d['ID'] == res_id ][0]['index']
      
      #TODO: for public network (with source node groups = 1), skip delete fault (with groups[delete] = 13)
      if not [ d for d in nodes if d['index'] == new_link['source'] and d['group'] == 1 and new_node['name'] == "delete" ]:

        #TODO: check duplicate fip
        if len(list_of_faults):
          if not [ d for d in list_of_faults if d['name'] == new_node['name'] and d['args'] == new_node['args'] and d['fault_target']['resource_faultID'] == new_node['fault_target']['resource_faultID'] and d['fault_pattern']['name'] == new_node['fault_pattern']['name'] and d['fault_target_traffic']['name'] == new_node['fault_target_traffic']['name'] ]:
            resp['nodes'].append(new_node)
            resp['links'].append(new_link)
            i += 1

        else:
          resp['nodes'].append(new_node)
          resp['links'].append(new_link)
          i += 1

    else:
      #TODO: Add code for link in physical mode 
      #new_link['source'] = [d for d in nodes if d['type'] == "resource" and d['ID'] == fip[4]][0]['index']
      res_index = 0

      if new_node['fault_target']['resource_type'] == "interface":
        node_list = [ d for d in links if d['source']['group'] == 8 ]
        for d in node_list:
          for d_fault_target in d['source']['fault_target']:
            if d_fault_target['value'] == fip[4]:
              res_index = d['source']['index']

      elif new_node['fault_target']['resource_type'] == "switch_port":
        node_list = [ d for d in links if d['target']['group'] == 7 ]
        for d in node_list:
          for d_fault_target in d['target']['fault_target']:
            if d_fault_target['value'] == fip[4]:
              res_index = d['target']['index']

      else:
        res_index = [ d for d in nodes if d['type'] == "resource" and d['ID'] == fip[4] ][0]['index']

      new_link['source'] = res_index

      #TODO: check duplicate fip
      if len(list_of_faults):
        if not [ d for d in list_of_faults if d['name'] == new_node['name'] and d['args'] == new_node['args'] and d['fault_target']['resource_faultID'] == new_node['fault_target']['resource_faultID'] and d['fault_pattern']['name'] == new_node['fault_pattern']['name'] and d['fault_target_traffic']['name'] == new_node['fault_target_traffic']['name'] ]:
          resp['nodes'].append(new_node)
          resp['links'].append(new_link)
          i += 1

      else:
        resp['nodes'].append(new_node)
        resp['links'].append(new_link)
        i += 1

  return json.dumps(resp)

@thorfi.route("/updateNetworkTopologyFromTable", methods=['POST'])
def updateNetworkTopologyFromTable():
  
  test_cases = request.form['testcases']
  nodes = json.loads(request.form['nodes'])
  links = json.loads(request.form['links'])

  ts = json.loads(str(test_cases))
  '''
    ts structure Array
                [ "tenant,component,resourceName,resourceID,faultType,args,description", 
                  "...",
                  "..."
                ]
  '''

  resp = {}
  resp['nodes'] = []
  resp['links'] = []

  groups =  { "public": 1,
              "router": 2,
              "net": 3,
              "subnet": 4,
              "server": 5,
              "loadBalancer": 6,
              "latency" : 10,
              "loss" : 11,
              "corrupt" : 12,
              "delete" : 13,
              "duplicate" : 14,
              "bottleneck" : 15,
              "down" : 16,
              "reboot" : 17
            }

  if current_user.urole == "virtual":
    #get list of ports and floating ip
    #get neutron client 
    thorfiAgent = getObjectRef(current_user.agent_ref)

    neutron_cli = thorfiAgent.getNeutronClientAuth()

    #get list of networks
    ports_list = neutron_cli.list_ports()
    floatingips_list = neutron_cli.list_floatingips()

  i = 0;
  for fip in ts:
    fip_array = fip.split('#')

    new_node = {}
    new_node['group'] = groups[fip_array[4]]
    new_node['name'] = fip_array[4]
    new_node['type'] = "fault"
    new_node['fault_target'] = {}
    new_node['fault_target']['resource_type'] = fip_array[1]
    new_node['fault_target']['resource_name'] = fip_array[2]
    new_node['fault_target']['resource_faultID'] = fip_array[3]
    new_node['args'] = fip_array[5]
    new_node['description'] = fip_array[6]

    new_node['fault_pattern'] = {}
    new_node['fault_pattern']['name'] = fip_array[7]
    new_node['fault_pattern']['args'] = {}
    new_node['fault_pattern']['args']['arg1'] = fip_array[8]
    new_node['fault_pattern']['args']['arg2'] = fip_array[9]

    new_node['fault_target_traffic'] = {}
    new_node['fault_target_traffic']['name'] = fip_array[10]
    new_node['fault_target_traffic']['args'] = {}
    new_node['fault_target_traffic']['args']['protocol'] = fip_array[11]
    new_node['fault_target_traffic']['args']['src_ports'] = fip_array[12]
    new_node['fault_target_traffic']['args']['dst_ports'] = fip_array[13]
    new_node['status'] = fip_array[14]

    new_link = {}
    
    new_link['target'] = len(nodes) + i;
    new_link['value'] = 0
    new_link['distance'] = 20

    if current_user.urole == "virtual":
      res_id = 0
      if new_node['fault_target']['resource_type'] == "port":
        #TODO: get correspondent owner (vm or router)
        res_id = [ d for d in ports_list['ports'] if d['id'] == new_node['fault_target']['resource_faultID'] ][0]['device_id']

      elif new_node['fault_target']['resource_type'] == "floatingip":
        #TODO: get correspondent owner (vm)
        port_id = [ d for d in floatingips_list['floatingips'] if d['floating_ip_address'] == new_node['fault_target']['resource_name'] ][0]['port_id']
        res_id = [ d for d in ports_list['ports'] if d['id'] == port_id ][0]['device_id']
      else:
        #TODO: get correspondent resource net, subnet, router.
        res_id = fip_array[3]

      new_link['source'] = [ d for d in nodes if d['type'] == "resource" and d['ID'] == res_id ][0]['index']

    else:
      #TODO: Add code for link in physical mode 
      #new_link['source'] = [d for d in nodes if d['type'] == "resource" and d['ID'] == fip_array[3]][0]['index']
      res_index = 0

      if new_node['fault_target']['resource_type'] == "interface":
        node_list = [ d for d in links if d['source']['group'] == 8 ]
        for d in node_list:
          for d_fault_target in d['source']['fault_target']:
            if d_fault_target['value'] == fip_array[3]:
              res_index = d['source']['index']

      elif new_node['fault_target']['resource_type'] == "switch_port":
        node_list = [ d for d in links if d['target']['group'] == 7 ]
        for d in node_list:
          for d_fault_target in d['target']['fault_target']:
            if d_fault_target['value'] == fip_array[3]:
              res_index = d['target']['index']

      else:
        res_index = [ d for d in nodes if d['ID'] == fip_array[3] ][0]['index']

      new_link['source'] = res_index

    resp['nodes'].append(new_node)
    resp['links'].append(new_link)
    i += 1

  return json.dumps(resp)

@thorfi.route("/generateTestPlan", methods=['POST'])
def generateTestPlan():
  """
      API for computing the fault injection test plain.  
      For each node['type'] == "fault" generate correspondent fip in fips_list.

      POST data:
            data_network_topology['nodes']
      Raises:
            #TODO:
  """

  nodes = json.loads(str(request.form['nodes']))
  fault_nodes = [d for d in nodes if d['type'] == "fault"]

  fips = []

  #fip = {}
  for fault_node in fault_nodes:
    fip = []
    fip.append('')
    #domain (tenant or infrastructure)
    if ( current_user.urole == "virtual" ):
      fip.append("tenant")
    else:
      fip.append("infrastructure")
    #component (i.e network, port, floatingip, ...) 
    fip.append(fault_node['fault_target']['resource_type'])
    #name of resource
    fip.append(fault_node['fault_target']['resource_name'])
    #target of injector (i.e. network => name , port => ID, floatingip => IP)
    fip.append(fault_node['fault_target']['resource_faultID'])
    #type of fault (i.e. latency, loss, corrupt, delete)
    fip.append(fault_node['name'])
    #arg
    fip.append(fault_node['args'])
    #description
    fip.append(fault_node['description'])
    
    #fault_pattern_name
    fip.append(fault_node['fault_pattern']['name'])
    #fault_pattern_arg_1
    fip.append(fault_node['fault_pattern']['args']['arg1']);
    #fault_pattern_arg_2
    fip.append(fault_node['fault_pattern']['args']['arg2']);

    #fault_target_traffic
    fip.append(fault_node['fault_target_traffic']['name'])
    #fault_target_traffic_protocol
    fip.append(fault_node['fault_target_traffic']['args']['protocol']);
    #fault_target_traffic_src_ports
    fip.append(fault_node['fault_target_traffic']['args']['src_ports']);
    #fault_target_traffic_dst_ports
    fip.append(fault_node['fault_target_traffic']['args']['dst_ports']);

    #status
    fip.append(fault_node['status'])

    fips.append(fip)

  return json.dumps(fips)



@thorfi.route("/saveTestCase", methods=['POST'])
def saveTestCase():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  flush_thorfi_log(thorfiAgent)

  logger = get_thorfi_app_logger(thorfiAgent)

  selected_test_case = request.form['testcases']
  ts = json.loads(str(selected_test_case))

  current_campaign_name = request.form['campaign_name']

  try:
    os.makedirs(thorfiAgent.getThorFIappDirPath() + '/Campaigns')
  except OSError:
    logger.debug("Campaigns folder already exists (pass). ")
    pass

  try:
    os.makedirs(thorfiAgent.getThorFIappDirPath() + '/Campaigns/' + current_user.user_signature)
  except OSError:
    logger.debug("Campaigns/%s folder already exists (pass). " % current_user.user_signature)
    pass

  try:
    os.makedirs(thorfiAgent.getThorFIappDirPath() + '/Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name )
  except OSError:
    logger.debug("Campaigns/%s/Campaign_%s folder already exists (pass). " % (current_user.user_signature, current_campaign_name ))
    pass

  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  #save selected_test_case on a file
  
  status_list = []
  fips_list = []

  print(ts)
  with open(campaign_path + '/fips_list.txt', 'w') as f:
    count = 1
    for fip in ts:
      f.write(str(count) + '#' +fip + '\n')
      status_list.append(str(count) + '#' + fip.split('#')[14])
      fips_list.append(str(count) + '#' + fip)
      count += 1
  with open(campaign_path + '/fips_status.txt', 'w') as f:
    for fip_status in status_list:
      f.write(fip_status + '\n')

  try:

    campaign_id = getCampaignID(current_user.user_signature, current_campaign_name)

    setTestsFromCampaign(campaign_id, fips_list)

  except Exception as ex:
    logger.error("Exceptions during createCampaign!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort (501)

  return "OK"


@thorfi.route("/getFipsList", methods=['POST'])
def getFipsList():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  thorfi_path = thorfiAgent.getThorFIrootDirPath() + '/'
  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  fips_list = []
  fips_status = []
  resp = []
  
  with open(campaign_path + '/fips_list.txt', 'r') as f:
    for fip in f.readlines():
      a = []
      a.append(fip[:-1].split('#'))
      #fips_list.append(fip[:-1])
      fips_list.append(a)
  #print(fips_list)    
  with open(campaign_path + '/fips_status.txt', 'r') as f:
    for fip_status in f.readlines():
      a = []
      a.append(fip_status[:-1].split('#'))
      #fips_status.append(fip_status[:-1])
      fips_status.append(a)
  #print (fips_status) 

  for index in range(len(fips_list)):
    a = []
    #print(fips_list[index])
    #print(fips_status[index][0][1])
    a.append(fips_list[index][0])
    a[0].append(fips_status[index][0][1])
    #resp.append(fips_list[index] + ',' + fips_status[index][2])
    resp.append(a)  
  #print(resp)
   
  return json.dumps(resp)

@thorfi.route("/status_tests", methods=['POST'])
def status_tests():
  
  thorfiAgent = getObjectRef(current_user.agent_ref)

  thorfi_path = thorfiAgent.getThorFIrootDirPath() + '/'
  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  resp = []

  try:

    with open(campaign_path + '/fips_status.txt', 'r') as f:
      for fip_status in f.readlines():
        a = []
        a.append(fip_status[:-1].split('#'))
        resp.append(a)

    return json.dumps(resp)

  except IOError:

    abort(404)

@thorfi.route("/networkslist", methods=['GET'])
def networkslist():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  #get neutron client 
  neutron_cli = thorfiAgent.getNeutronClientAuth()
  
  #get list of networks
  networks = neutron_cli.list_networks()

  resp = {}
  resp['networks'] = []

  for network in networks['networks']:
    if not network['router:external'] and network['project_id'] != current_user.project_id:
      #networks['networks'].remove(network)
      pass
    else:
      resp['networks'].append(network)    

  return json.dumps(resp)

@thorfi.route('/portslist', methods=['GET'])
def portslist():
 
  thorfiAgent = getObjectRef(current_user.agent_ref)
 
  #get neutron clien
  neutron_cli = thorfiAgent.getNeutronClientAuth()
  #get list of ports
  ports = neutron_cli.list_ports(project_id=current_user.project_id)
  #filter ports['device_owner'] == network:dhcp
  ports['ports'] = [ d for d in ports['ports'] if d['device_owner'] != "network:dhcp" ]
  #this filtering not return network: router gateway port, because these ports are project_id null
  return json.dumps(ports)

@thorfi.route('/routerslist', methods=['GET'])
def routerslist():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  #get neutron clien
  neutron_cli = thorfiAgent.getNeutronClientAuth()
  #get list of routers
  routers = neutron_cli.list_routers(project_id=current_user.project_id)

  return json.dumps(routers)


@thorfi.route('/floatingipslist', methods=['GET'])
def floatingipslist():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  #get neutron clien
  neutron_cli = thorfiAgent.getNeutronClientAuth()
  #get list of floating ips
  floatingips = neutron_cli.list_floatingips(project_id=current_user.project_id, status="ACTIVE")

  return json.dumps(floatingips)

@thorfi.route('/subnetslist', methods=['GET'])
def subnetslist():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  #get neutron clien
  neutron_cli = thorfiAgent.getNeutronClientAuth()
  #get list of floating ips
  subnets = neutron_cli.list_subnets(project_id=current_user.project_id)

  return json.dumps(subnets)

@thorfi.route('/setInjectorTime', methods=['POST'])
def setInjectorTime():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  campaign_name = request.form['campaign_name']

  pre_injection_time = request.form['pre_injection_time']
  injection_time = request.form['injection_time']
  post_injection_time = request.form['post_injection_time']

  injector_time_params = {}
  injector_time_params['pre_injection_time'] = pre_injection_time
  injector_time_params['injection_time'] = injection_time
  injector_time_params['post_injection_time'] = post_injection_time

  try:
    campaign_id = getCampaignID(current_user.user_signature, campaign_name)

    setTime_Conf(campaign_id, injector_time_params)

    return "OK"

  except Exception as ex:

    logger.error("Exceptions during setInjectorTime!")
    logger.error("Raised exception %s" % ex)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort(501)





@thorfi.route('/getInjectorTime', methods=['POST'])
def getInjectorTime():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  injector_time_params = {}

  campaign_name = request.form['campaign_name']

  try:
    campaign_id = getCampaignID(current_user.user_signature, campaign_name)

    injector_time_params = getTime_Conf(campaign_id)

    return json.dumps(injector_time_params)

  except Exception as ex:

        logger.error("Exceptions during getInjectorTime!")
        logger.error("Raised exception %s" % ex)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
        abort(501)


@thorfi.route('/getJmeterAllTest_average', methods=['POST'])
def getJmeterAllTest_average():

  '''
    compute average statistics for all jmeter test in campaign
  '''

  thorfiAgent = getObjectRef(current_user.agent_ref)

  logger = get_thorfi_app_logger(thorfiAgent)

  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  resp = {}
  resp['tests'] = []

  resp['throughput_req_sec'] = []
  resp['throughput_req_sec_pre'] = 0

  resp['error_rate'] = []
  resp['error_rate_pre'] = 0

  resp['throughput_bytes_sec'] = []
  resp['throughput_bytes_sec_pre'] = 0

  resp['elapsed_time'] = []
  resp['elapsed_time_pre'] = 0

  resp['conn_timeout'] = []
  resp['conn_timeout_pre'] = 0

  resp['resp_timeout'] = []
  resp['resp_timeout_pre'] = 0

  array_pre_throughput_req_sec = []
  array_pre_error_rate = []  
  array_pre_throughput_bytes_sec = []
  array_pre_elapsed_time = [] 
  array_pre_conn_timeout = [] 
  array_pre_resp_timeout = []

  try:
    with open(campaign_path + '/injection_setup.json', 'r') as file:
      injector_time_params = json.loads(file.read())
  except IOError as e:
      abort(404)

  test_array = json.loads(str(request.form['tests']))
  print (test_array)
  test_array_folder = []
  for test in test_array:
    test_array_folder.append(test.replace("test_", "Test_"))

  for test in test_array_folder:
    timestamp_array = []
    time_sec = []
    time_x = []
    success_y = []
    error_y = []
    bytes_y = []
    elapsed_y = []
    latency_y = []
    connect_y = []
    conn_timeout_y = []
    resp_timeout_y = []
    samples = 0
    
    try:
      with open(campaign_path + '/' + test + '/summary.csv', mode = 'rt') as file:
        reader = csv.reader(file, delimiter=',')
        sorted1 = sorted(reader, key=lambda row: int(row[0]))
        resp['tests'].append(test.replace("Test_", "test_"))

        for row in sorted1:
          timestamp_array.append((int(row[0])))

        timestamp_0 = timestamp_array[0]
        for timestamp in timestamp_array:
          time_sec.append(((timestamp - timestamp_0)/1000)+1)

        samples = len(timestamp_array)

        tmp_time = None
        index = 0
        time_sec_sum = []

        for t in time_sec:
          if not (t == tmp_time):
            time_sec_sum.append(1)
            tmp_time = t
            index += 1
          else:
            time_sec_sum[index - 1] += 1

        index = 0
        for elem in time_sec_sum:
          tmp_time = time_sec[index]
          tmp_success_y = 0
          tmp_error_y = 0
          tmp_bytes_y = 0
          tmp_elapsed_y = 0
          tmp_latency_y = 0
          tmp_connect_y = 0
          tmp_conn_timeout = 0
          tmp_resp_timeout = 0

          for i in range(elem):
            tmp_bytes_y += int(sorted1[index][9])
            tmp_elapsed_y += int(sorted1[index][1])
            tmp_latency_y += int(sorted1[index][14])
            tmp_connect_y += int(sorted1[index][16])
            if not sorted1[index][3] == "200":
              tmp_error_y += 1
              if 'ConnectTimeoutException' in sorted1[index][3]:
                tmp_conn_timeout += 1
              elif 'SocketTimeoutException' in sorted1[index][3]:
                tmp_resp_timeout += 1
            else:
              tmp_success_y += 1
            index += 1

          time_x.append(tmp_time)
          success_y.append(tmp_success_y)
          error_y.append(tmp_error_y)
          conn_timeout_y.append(tmp_conn_timeout)
          resp_timeout_y.append(tmp_resp_timeout)
          bytes_y.append(tmp_bytes_y)
          if tmp_success_y:
            elapsed_y.append(tmp_elapsed_y / tmp_success_y)
            latency_y.append(tmp_latency_y / tmp_success_y)
            connect_y.append(tmp_connect_y / tmp_success_y)
          else:
            elapsed_y.append(tmp_elapsed_y)
            latency_y.append(tmp_latency_y)
            connect_y.append(tmp_connect_y)

      array_pre_injection_time = []
      array_during_injection_time = []

      array_throughput_req_sec_pre_injection = []
      array_throughput_req_sec_during_injection = []

      array_error_rate_pre_injection = []
      array_error_rate_during_injection = []

      array_throughput_bytes_sec_pre_injection = []
      array_throughput_bytes_sec_during_injection = []

      array_elapsed_time_pre_injection = []
      array_elapsed_time_during_injection = []

      array_conn_timeout_pre_injection = []
      array_conn_timeout_during_injection = []

      array_resp_timeout_pre_injection = []
      array_resp_timeout_during_injection = []

      for i in range(len(time_x)):
        if ( time_x[i] < int(injector_time_params['pre_injection_time']) ):
          array_pre_injection_time.append(time_x[i])
          array_throughput_req_sec_pre_injection.append(success_y[i])
          array_error_rate_pre_injection.append(error_y[i])
          array_throughput_bytes_sec_pre_injection.append(bytes_y[i]/1024)
          array_elapsed_time_pre_injection.append(elapsed_y[i])
          array_conn_timeout_pre_injection.append(conn_timeout_y[i])
          array_resp_timeout_pre_injection.append(resp_timeout_y[i])

        elif ( time_x[i] >= int(injector_time_params['pre_injection_time']) and time_x[i] < (int(injector_time_params['pre_injection_time']) + int(injector_time_params['injection_time'])) ):
          array_during_injection_time.append(time_x[i])
          array_throughput_req_sec_during_injection.append(success_y[i])
          array_error_rate_during_injection.append(error_y[i])
          array_throughput_bytes_sec_during_injection.append(bytes_y[i]/1024)
          array_elapsed_time_during_injection.append(elapsed_y[i])
          array_conn_timeout_during_injection.append(conn_timeout_y[i])
          array_resp_timeout_during_injection.append(resp_timeout_y[i])

      '''
      print("TEST => %s" %test)
      print ("array_conn_timeout_pre_injection %s" %array_conn_timeout_pre_injection)
      print ("array_resp_timeout_pre_injection %s" %array_resp_timeout_pre_injection)

      print("TEST => %s" %test)
      print ("array_conn_timeout_during_injection %s" %array_conn_timeout_during_injection)
      print ("array_resp_timeout_during_injection %s" %array_resp_timeout_during_injection)
      '''

      try:
        resp['throughput_req_sec'].append(sum(array_throughput_req_sec_during_injection) / len(array_throughput_req_sec_during_injection))
      except ZeroDivisionError as error:
        resp['throughput_req_sec'].append(0)
        
      try:
        resp['error_rate'].append(format(((sum(array_error_rate_during_injection)*1.0)/samples)*100, '.2f'))
      except ZeroDivisionError as error:
        resp['error_rate'].append(0)

      try:  
        resp['throughput_bytes_sec'].append(sum(array_throughput_bytes_sec_during_injection) / len(array_throughput_bytes_sec_during_injection))
      except ZeroDivisionError as error:
        resp['throughput_bytes_sec'].append(0)

      try:
        resp['elapsed_time'].append(sum(array_elapsed_time_during_injection) / len(array_elapsed_time_during_injection))
      except ZeroDivisionError as error:
        resp['elapsed_time'].append(0)

      try:
        resp['conn_timeout'].append(format(((sum(array_conn_timeout_during_injection)*1.0)/samples)*100, '.2f'))
      except ZeroDivisionError as error:
        resp['conn_timeout'].append(0)

      try:
        resp['resp_timeout'].append(format(((sum(array_resp_timeout_during_injection)*1.0)/samples)*100, '.2f'))
      except ZeroDivisionError as error:
        resp['resp_timeout'].append(0)


      try:
        array_pre_throughput_req_sec.append(sum(array_throughput_req_sec_pre_injection) / len(array_throughput_req_sec_pre_injection))
      except ZeroDivisionError as error:
        array_pre_throughput_req_sec.append(0)        

      try:
        array_pre_error_rate.append(((sum(array_error_rate_pre_injection)*1.0)/samples)*100)
      except ZeroDivisionError as error:
        array_pre_error_rate.append(0)

      try:
        array_pre_throughput_bytes_sec.append(sum(array_throughput_bytes_sec_pre_injection) / len(array_throughput_bytes_sec_pre_injection))
      except ZeroDivisionError as error:
        array_pre_throughput_bytes_sec.append(0)

      try:  
        array_pre_elapsed_time.append(sum(array_elapsed_time_pre_injection) / len(array_elapsed_time_pre_injection))
      except ZeroDivisionError as error:
        array_pre_elapsed_time.append(0)

      try:
        array_pre_conn_timeout.append(((sum(array_conn_timeout_pre_injection)*1.0)/samples)*100)
      except ZeroDivisionError as error:
        array_pre_conn_timeout.append(0)

      try:
        array_pre_resp_timeout.append(((sum(array_resp_timeout_pre_injection)*1.0)/samples)*100)
      except ZeroDivisionError as error:
        array_pre_resp_timeout.append(0)

      '''
      print("TEST => %s" %test)
      print ("array_pre_conn_timeout %s" %array_pre_conn_timeout)
      print ("array_pre_resp_timeout %s" %array_pre_resp_timeout)
      '''

    except IOError as error:
      abort(404)

    except Exception as ex:
      logger.error("Exceptions during getJmeterAllTest_average!")
      logger.error("Raised exception %s" % ex)
      exc_type, exc_value, exc_traceback = sys.exc_info()
      traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
      abort(501)

  try:
    resp['throughput_req_sec_pre'] = sum(array_pre_throughput_req_sec) / len(array_pre_throughput_req_sec)
    resp['error_rate_pre'] = format(((sum(array_pre_error_rate)*1.0) / len(array_pre_error_rate)), '.2f')
    resp['throughput_bytes_sec_pre'] = sum(array_pre_throughput_bytes_sec) / len(array_pre_throughput_bytes_sec)
    resp['elapsed_time_pre'] = sum(array_pre_elapsed_time) / len(array_pre_elapsed_time)
    resp['conn_timeout_pre'] = format(((sum(array_pre_conn_timeout)*1.0) / len(array_pre_conn_timeout)), '.2f')
    resp['resp_timeout_pre'] = format(((sum(array_pre_resp_timeout)*1.0) / len(array_pre_resp_timeout)), '.2f')
  except ZeroDivisionError as error:
    logger.error("Exceptions ZeroDivisionError during getJmeterAllTest_average!")
    logger.error("Raised exception %s" % error)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
    abort(501)

  
  return json.dumps(resp)

@thorfi.route('/getIperfAllTest_UDP_average', methods=['POST'])
def getIperfAllTest_UDP_average():

  """
    compute average statistics for all UDP test in campaign
  """
  thorfiAgent = getObjectRef(current_user.agent_ref)
  
  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  resp = {}
  resp['tests_server'] = []
  resp['bandwidth_server'] = []
  resp['pre_bandwidth_server'] = 0
  resp['sent_lost_server'] = []
  resp['pre_sent_lost_server'] = 0

  array_pre_bandwidth_server = []
  array_pre_sent_lost_server = []  

  try:
    with open(campaign_path + '/injection_setup.json', 'r') as file:
      injector_time_params = json.loads(file.read())
  except IOError as e:
      abort(404)

  test_array = json.loads(str(request.form['tests']))
  print (test_array)
  test_array_folder = []
  for test in test_array:
    test_array_folder.append(test.replace("test_", "Test_"))

  for test in test_array_folder:
    try:
      with open(campaign_path + '/' + test + '/iperf_server.log', 'r') as file:

        parsed = parse_json_log_file(file)
        iperf_server_log_udp = json.loads(parsed);

      if (iperf_server_log_udp['start']['test_start']['protocol'] == "UDP"):
        
        resp['tests_server'].append(test.replace("Test_", "test_"))

        timeData = []
        bandwidth = []
        send_packets = []
        lost_packets = []

        for intervals in iperf_server_log_udp['intervals']:
          timeData.append(int(intervals['streams'][0]['end']))
          bandwidth.append(int(intervals['streams'][0]['bits_per_second'] / 1024))
          send_packets.append(intervals['streams'][0]['packets'])
          lost_packets.append(intervals['streams'][0]['lost_packets'])

        array_pre_injection_time = []
        array_during_injection_time = []

        array_bandwidth_pre_injection = []
        array_bandwidth_during_injection = []

        array_send_packets_pre_injection = []
        array_send_packets_during_injection = []

        array_lost_packets_pre_injection = []
        array_lost_packets_during_injection = []

        for i in range(len(timeData)):
          if (timeData[i] < int(injector_time_params['pre_injection_time'])):
            array_pre_injection_time.append(timeData[i])
            array_bandwidth_pre_injection.append(bandwidth[i])
            array_send_packets_pre_injection.append(send_packets[i])
            array_lost_packets_pre_injection.append(lost_packets[i])

          if (timeData[i] >= int(injector_time_params['pre_injection_time']) and timeData[i] < (int(injector_time_params['pre_injection_time']) + int(injector_time_params['injection_time']))):
            array_during_injection_time.append(timeData[i])
            array_bandwidth_during_injection.append(bandwidth[i])
            array_send_packets_during_injection.append(send_packets[i])
            array_lost_packets_during_injection.append(lost_packets[i])

        resp['bandwidth_server'].append(reduce(lambda x, y: x + y, array_bandwidth_during_injection) / len(array_bandwidth_during_injection))
        resp['sent_lost_server'].append((reduce(lambda x, y: x + y, array_lost_packets_during_injection) / reduce(lambda x, y: x + y, array_send_packets_during_injection))*100)
        array_pre_bandwidth_server.append(reduce(lambda x, y: x + y, array_bandwidth_pre_injection) / len(array_bandwidth_pre_injection))
        array_pre_sent_lost_server.append(reduce(lambda x, y: x + y, array_lost_packets_during_injection) / reduce(lambda x, y: x + y, array_send_packets_during_injection))

      else:
        pass  
    except IOError as e:
      abort(404)
    except ArithmeticError as e:
      abort(501)

  try:
    resp['pre_bandwidth_server'] = reduce(lambda x, y: x + y, array_pre_bandwidth_server) / len(array_pre_bandwidth_server)
    resp['pre_sent_lost_server'] = (reduce(lambda x, y: x + y, array_pre_sent_lost_server) / len(array_pre_sent_lost_server)) * 100
  except ArithmeticError as e:
    abort(501)

  return json.dumps(resp)


@thorfi.route('/getIperfAllTest_TCP_average', methods=['POST'])
def getIperfAllTest_TCP_average():

  """
    compute average statistics for all TCP test in campaign
  """
  thorfiAgent = getObjectRef(current_user.agent_ref)
  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  resp = {}
  resp['tests_client'] = []
  resp['bandwidth_client'] = []
  resp['pre_bandwidth_client'] = 0
  resp['rtt_client'] = []
  resp['pre_rtt_client'] = 0
  resp['bandwidth_server'] = []
  resp['pre_bandwidth_server'] = 0


  array_pre_bandwidth_client = []
  array_pre_rtt_client = []
  
  array_pre_bandwidth_server = []
  

  try:
    with open(campaign_path + '/injection_setup.json', 'r') as file:
      injector_time_params = json.loads(file.read())
  except IOError as e:
      abort(404)

  test_array = json.loads(str(request.form['tests']))
  test_array_folder = []
  for test in test_array:
    test_array_folder.append(test.replace("test_", "Test_"))

  #TCP client log
  for test in test_array_folder:
    try:

      with open(campaign_path + '/' + test + '/iperf_client.log', 'r') as file:

        parsed = parse_json_log_file(file)
        iperf_client_log_tcp = json.loads(parsed);

      if not (parsed in '{}'):

        if (iperf_client_log_tcp['start']['test_start']['protocol'] == "TCP"):
          
          resp['tests_client'].append(test.replace("Test_", "test_"))

          timeData = []
          bandwidth = []
          rtt = []

          for intervals in iperf_client_log_tcp['intervals']:
            timeData.append(int(intervals['streams'][0]['end']))
            bandwidth.append(int(intervals['streams'][0]['bits_per_second'] / 1024))
            rtt.append(intervals['streams'][0]['rtt'] / 1000000)


          array_pre_injection_time = []
          array_during_injection_time = []

          array_bandwidth_pre_injection = []
          array_bandwidth_during_injection = []

          array_rtt_pre_injection = []
          array_rtt_during_injection = []
    
          for i in range(len(timeData)):
            if (timeData[i] < int(injector_time_params['pre_injection_time'])):
              
              array_pre_injection_time.append(timeData[i])
              array_bandwidth_pre_injection.append(bandwidth[i])
              array_rtt_pre_injection.append(rtt[i])

            if (timeData[i] >= int(injector_time_params['pre_injection_time']) and timeData[i] < (int(injector_time_params['pre_injection_time']) + int(injector_time_params['injection_time']))):
              array_during_injection_time.append(timeData[i])
              array_bandwidth_during_injection.append(bandwidth[i])
              array_rtt_during_injection.append(rtt[i])

          print("timeData------------: %s" % timeData)

          print array_bandwidth_during_injection
          print array_rtt_during_injection
          print array_bandwidth_pre_injection
          print array_rtt_pre_injection

          resp['bandwidth_client'].append(reduce(lambda x, y: x + y, array_bandwidth_during_injection) / len(array_bandwidth_during_injection))
          resp['rtt_client'].append(reduce(lambda x, y: x + y, array_rtt_during_injection) / len(array_rtt_during_injection))
          array_pre_bandwidth_client.append(reduce(lambda x, y: x + y, array_bandwidth_pre_injection) / len(array_bandwidth_pre_injection))
          array_pre_rtt_client.append(reduce(lambda x, y: x + y, array_rtt_pre_injection) / len(array_rtt_pre_injection))

        else:
          pass  
    except IOError as e:
      abort(404)
    except ArithmeticError as e:
      abort(501)

  try:
    resp['pre_bandwidth_client'] = reduce(lambda x, y: x + y, array_pre_bandwidth_client) / len(array_pre_bandwidth_client)
    resp['pre_rtt_client'] = reduce(lambda x, y: x + y, array_pre_rtt_client) / len(array_pre_rtt_client)
  except ArithmeticError as e:
      abort(501)

  #TCP server log
  for test in test_array_folder:
    try:
      with open(campaign_path + '/' + test + '/iperf_server.log', 'r') as file:

        parsed = parse_json_log_file(file)
        iperf_server_log_tcp = json.loads(parsed)

      if not (parsed in '{}'):

          if (iperf_server_log_tcp['start']['test_start']['protocol'] == "TCP"):

            timeData = []
            bandwidth = []

            for intervals in iperf_server_log_tcp['intervals']:
              timeData.append(int(intervals['streams'][0]['end']))
              bandwidth.append(int(intervals['streams'][0]['bits_per_second'] / 1024))

            array_pre_injection_time = []
            array_during_injection_time = []

            array_bandwidth_pre_injection = []
            array_bandwidth_during_injection = []

            for i in range(len(timeData)):
              if (timeData[i] < int(injector_time_params['pre_injection_time'])):
                array_pre_injection_time.append(timeData[i])
                array_bandwidth_pre_injection.append(bandwidth[i])

              if (timeData[i] >= int(injector_time_params['pre_injection_time']) and timeData[i] < (int(injector_time_params['pre_injection_time']) + int(injector_time_params['injection_time']))):
                array_during_injection_time.append(timeData[i])
                array_bandwidth_during_injection.append(bandwidth[i])

            resp['bandwidth_server'].append(reduce(lambda x, y: x + y, array_bandwidth_during_injection) / len(array_bandwidth_during_injection))
            
            array_pre_bandwidth_server.append(reduce(lambda x, y: x + y, array_bandwidth_pre_injection) / len(array_bandwidth_pre_injection))

          else:
            pass  
    except IOError as e:
      abort(404)

  resp['pre_bandwidth_server'] = reduce(lambda x, y: x + y, array_pre_bandwidth_server) / len(array_pre_bandwidth_server)

  return json.dumps(resp)



@thorfi.route('/getIperfLog', methods=["POST"])
def getIperfLog():

  thorfiAgent = getObjectRef(current_user.agent_ref)  
  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  test_id = request.form['test']
  test_path = campaign_path + '/Test_' + test_id + '/'
  log_type = request.form['log_type']

  log_file = test_path + 'iperf_'+ log_type +'.log'

  parsed = None
  try:
    with open(log_file, 'r') as file: 

      #check correcteness of json log file

      parsed = parse_json_log_file(file)

      return json.dumps(json.loads(parsed))

      #return json.dumps(json.loads(file.read()))
  except IOError:
      #return json.dumps(log_file + " NotFound")
      abort(404)


@thorfi.route('/getJmeterLog', methods=["POST"])
def getJmeterLog():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  test_id = request.form['test']
  test_path = campaign_path + '/Test_' + test_id + '/'
  jmeter_log_file = test_path + 'summary.csv'

  resp = {}
  resp['time'] = []
  resp['throughput_req_sec'] = []
  resp['error_rate'] = []
  resp['throughput_bytes_sec'] = []
  resp['elapsed_time'] = []
  resp['conn_timeout'] = []
  resp['resp_timeout'] = []

  time_csv = []
  throughput_req_sec_csv = []
  error_rate_csv = []
  throughput_bytes_sec_csv = []
  elapsed_time_csv = []
  conn_timeout_csv = []
  resp_timeout_csv = []

  timestamp_array = []
  time_sec = []
  latency_y = []
  connect_y = []
  
  try:  
    with open(jmeter_log_file, mode = 'rt') as file:
      reader = csv.reader(file, delimiter=',')
      sorted1 = sorted(reader, key=lambda row: int(row[0]))

      for row in sorted1:
        timestamp_array.append((int(row[0])))

      timestamp_0 = timestamp_array[0]
      for timestamp in timestamp_array:
        time_sec.append(((timestamp - timestamp_0)/1000)+1)

      tmp_time = None
      index = 0
      time_sec_sum = []

      for t in time_sec:
        if not (t == tmp_time):
          time_sec_sum.append(1)
          tmp_time = t
          index += 1
        else:
          time_sec_sum[index - 1] += 1

      index = 0
      for elem in time_sec_sum:
        tmp_time = time_sec[index]
        tmp_success_y = 0
        tmp_error_y = 0
        tmp_bytes_y = 0
        tmp_elapsed_y = 0
        tmp_latency_y = 0
        tmp_connect_y = 0
        tmp_conn_timeout = 0
        tmp_resp_timeout = 0

        for i in range(elem):
          tmp_bytes_y += int(sorted1[index][9])
          tmp_elapsed_y += int(sorted1[index][1])
          tmp_latency_y += int(sorted1[index][14])
          tmp_connect_y += int(sorted1[index][16])
          if not sorted1[index][3] == "200":
            tmp_error_y += 1
            if 'ConnectTimeoutException' in sorted1[index][3]:
              tmp_conn_timeout += 1
            elif 'SocketTimeoutException' in sorted1[index][3]:
              tmp_resp_timeout += 1
          else:
            tmp_success_y += 1
          index += 1

        time_csv.append(tmp_time)
        throughput_req_sec_csv.append(tmp_success_y)
        error_rate_csv.append(tmp_error_y)
        conn_timeout_csv.append(tmp_conn_timeout)
        resp_timeout_csv.append(tmp_resp_timeout)
        throughput_bytes_sec_csv.append(tmp_bytes_y)
        if tmp_success_y:
          elapsed_time_csv.append(tmp_elapsed_y / tmp_success_y)
          latency_y.append(tmp_latency_y / tmp_success_y)
          connect_y.append(tmp_connect_y / tmp_success_y)
        else:
          elapsed_time_csv.append(tmp_elapsed_y)
          latency_y.append(tmp_latency_y)
          connect_y.append(tmp_connect_y)

      #Padding zero for the jmeter graphs
      for i in range(max(time_csv)+1):
        resp['time'].append(i)

      index = 0

      for i in resp['time']:
        if i in time_csv:
          resp['throughput_req_sec'].append(throughput_req_sec_csv[index])
          resp['error_rate'].append(error_rate_csv[index])
          resp['throughput_bytes_sec'].append(throughput_bytes_sec_csv[index])
          resp['elapsed_time'].append(elapsed_time_csv[index])
          resp['conn_timeout'].append(conn_timeout_csv[index])
          resp['resp_timeout'].append(resp_timeout_csv[index])

          index += 1
        else:
          resp['throughput_req_sec'].append(0)
          resp['error_rate'].append(0)
          resp['throughput_bytes_sec'].append(0)
          resp['elapsed_time'].append(0)
          resp['conn_timeout'].append(0)
          resp['resp_timeout'].append(0)

      return json.dumps(resp)          

  except IOError:
    abort(404)

  except Exception:
    abort(501)
  
  

def create_thorfi_stack(heat_client, thorfi_stack_name, thorfi_stack_template, thorfi_stack_params):

    """
        'create_thorfi_stack' create the thorfi stack according to the workload template

        Args:
            heat_client: heat client ref
            thorfi_stack_name: stack name
            thorfi_stack_template: template path
            thorfi_stack_params: template parameters
        Returns:
            stack_ref: stack object reference
    """
    #try:
    template = open(thorfi_stack_template)
    stack_ref = heat_client.stacks.create(stack_name=thorfi_stack_name, template=template.read(), parameters=thorfi_stack_params)
    #except:
    #    raise ThorFIStackCreationException(thorfi_stack_name)

    return stack_ref

def update_thorfi_stack(heat_client, thorfi_stack_id, thorfi_stack_name, thorfi_stack_template, thorfi_stack_params):

    """
        'update_thorfi_stack' update the thorfi stack according to the workload template

        Args:
            heat_client: heat client ref
            thorfi_stack_name: stack name
            thorfi_stack_template: template path
            thorfi_stack_params: template parameters
        Returns:
            stack_ref: stack object reference
    """
    #try:
    template = open(thorfi_stack_template)
    heat_client.stacks.update(thorfi_stack_id, stack_name=thorfi_stack_name, template=template.read(), parameters=thorfi_stack_params, existing=True)
    #except:
    #    raise ThorFIStackUpdateException(thorfi_stack_name)



def delete_thorfi_stack(heat_client, thorfi_stack_name):

    """
        'delete_thorfi_stack' delete the thorfi stack with name 'thorfi_stack_name'

        Args:
            heat_client: heat client ref
            thorfi_stack_name: stack name
            
    """
    
    try:
        heat_client.stacks.delete(thorfi_stack_name)
    except:
        raise ThorFIStackDeletionException(thorfi_stack_name)

def check_thorfi_stack_status(heat_client, stack_id, desired_status):
    
    curr_stack_status = ''

    while True:
        if desired_status not in curr_stack_status:
            time.sleep(1)
            curr_stack_status = heat_client.stacks.get(stack_id).stack_status
        else:
            break
    return curr_stack_status

def check_thorfi_flavor(nova_client, flavor_name):

    for flavor in nova_client.flavors.list():
        if flavor_name in flavor.name:
            return True

    return False

def get_iperf_instances_ips(stack_outputs, public_ip_type):

    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)
    
    for el in stack_outputs:
  
        if el['output_key'] in public_ip_type:
            public_ip = el['output_value']
            logger.info("FOUND ip %s:%s" % (el['output_key'], el['output_value']))
            return public_ip

    return None

def check_instances_reachability(ips_lists, max_retries):

    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    try:

      for ip in ips_lists:

          logger.debug("Wait for host %s if is reachable...(max_retries: %s)" % (ip, max_retries))

          if check_reachability(ip, max_retries):
              logger.debug("Host %s is reachable!" % ip)
          else:
              logger.debug("Host %s is not reachable (timeout %s s)!" % (ip, max_retries))
              raise Exception

    except:
      #TODO: raise exception specific for openstack stack operations
      raise Exception

@thorfi.route('/deploy_workload_instances_fake', methods=['POST'])
def deploy_workload_instances_fake():

  sleep(7)
  return "OK"

@thorfi.route('/start_tests_fake', methods=['POST'])
def start_tests_fake():

  sleep(7)
  return "OK"


@thorfi.route('/deploy_workload_instances_phy', methods=['POST'])
def deploy_workload_instances_phy():
  """
      'deploy_workload_instances_phy' deploys the workload generator iperf3 and jmeter in the physical mode.
      In this case, the API configure some attribute in the thorfiAgent such: workload_type, iperf_server_ip/port, etc...

  """

  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  workload_type = request.form['workload_type']

  if 'iperf' in workload_type:

    workload_params = { 
                        'iperf_client_ip' : request.form['iperf_client_ip'],
                        'iperf_server_ip' : request.form['iperf_server_ip'],
                        'iperf_server_port' : request.form['iperf_server_port'],
                        'iperf_bandwidth' : request.form['iperf_bandwidth'],
                        'iperf_protocol' : request.form['iperf_protocol']
                      }

    logger.debug("iperf_client_ip: %s" % workload_params['iperf_client_ip'])
    logger.debug("iperf_server_ip: %s" % workload_params['iperf_server_ip'])
    logger.debug("iperf_server_port: %s" % workload_params['iperf_server_port'])

  elif 'jmeter' in workload_type:

    #jmeter_client_name = request.form['jmeter_client_name']

    workload_params = {
                        'jmeter_client_ip' : request.form['jmeter_client_ip'],
                        'jmeter_server_ip' : request.form['jmeter_server_ip'],
                        'jmeter_server_port' : request.form['jmeter_server_port'],
                        'jmeter_page_file_path': request.form['jmeter_page_file_path'],
                        'jmeter_http_method': request.form['jmeter_http_method'],
                        'jmeter_connection_timeout': request.form['jmeter_connection_timeout'],
                        'jmeter_response_timeout' : request.form['jmeter_response_timeout'],
                        'jmeter_troughput_value' : request.form['jmeter_troughput_value']
                   }

    logger.debug("jmeter_server_ip: %s" % workload_params['jmeter_server_ip'])
    logger.debug("jmeter_server_port: %s" % workload_params['jmeter_server_port'])
    logger.debug("jmeter_page_file_path: %s" % workload_params['jmeter_page_file_path'])
    logger.debug("jmeter_http_method: %s" % workload_params['jmeter_http_method'])
    logger.debug("jmeter_connection_timeout: %s" % workload_params['jmeter_server_ip'])
    logger.debug("jmeter_response_timeout: %s" % workload_params['jmeter_response_timeout'])
    logger.debug("jmeter_troughput_value: %s" % workload_params['jmeter_troughput_value'])

  logger.info("Starting deploying workload instances for the workload type: '%s'" % workload_type)

  #save stack ID, workload type, and workload params, to execute workload on it later
  '''
  thorfiWorkload = ThorFIWorkload(  
                                      logger=logger, 
                                      workload_type=workload_type, 
                                      workload_params=workload_params,
                                      thorfi_key_path=thorfiAgent.getThorFIappDirPath() + '/thorfi.key'
                                    )
  
  thorfiAgent.setThorFIWorkloadRef(thorfiWorkload)
  '''
  logger.info("LOG FILE PATH: %s" % thorfiAgent.getThorFILogFileName())
  thorfiWorkload = ThorFIWorkload(
                                      thorfi_log_file=thorfiAgent.getThorFILogFileName(),
                                      workload_type=workload_type,
                                      workload_params=workload_params,  
                                      thorfi_key_path=thorfiAgent.getThorFIappDirPath() + '/thorfi.key'
                                    )

  thorfiAgent.setThorFIWorkloadRef(thorfiWorkload)

  #we need to refresh pickled object
  refreshed_agent_ref = pickle.dumps(thorfiAgent)
  update_user_agent_ref(current_user.user_signature, refreshed_agent_ref)

  return "OK"


@thorfi.route('/deploy_workload_instances', methods=['POST'])
def deploy_workload_instances():

    """
        'deploy_workload_instances' deploys the openstack instances according to the specified workload type.
        In the current ThorFI version we implement only iperf3 and JMeter workloads.
        In general, we execute the following steps:
          1. get thorfi image reference (create it if does not exist)
          2. deploy the instances according to workload type
    """

    thorfiAgent = getObjectRef(current_user.agent_ref)

    logger = get_thorfi_app_logger(thorfiAgent)

    neutron_client = thorfiAgent.getNeutronClientAuth()

    # if we invoke 'deploy_workload_instances' as POST...
    if request.method == 'POST':

        workload_type = request.form['workload_type']

        thorfi_stack_params = {}

        if 'iperf' in workload_type:
            
            private_net_ID_iperf_client= request.form['private_net_ID_iperf_client']
            private_subnet_ID_iperf_client = request.form['private_subnet_ID_iperf_client']
            private_net_ID_iperf_server = request.form['private_net_ID_iperf_server']
            private_subnet_ID_iperf_server = request.form['private_subnet_ID_iperf_server']
        
            logger.debug("private_net_ID_iperf_client: %s" % private_net_ID_iperf_client)
            logger.debug("private_subnet_ID_iperf_client: %s" % private_subnet_ID_iperf_client)
            logger.debug("private_net_ID_iperf_server: %s" % private_net_ID_iperf_server)
            logger.debug("private_subnet_ID_iperf_server: %s" % private_subnet_ID_iperf_server)

            #check public network id linked to private_net_ID_iperf_client and private_net_ID_iperf_server

            private_net_ID_iperf_client_router = neutron_client.list_ports(network_id=private_net_ID_iperf_client, device_owner='network:router_interface ')['ports'][0]['device_id']

            if private_net_ID_iperf_client_router:
                public_net_ID_iperf_client = neutron_client.list_routers(id=private_net_ID_iperf_client_router)['routers'][0]['external_gateway_info']['network_id']

            private_net_ID_iperf_server_router = neutron_client.list_ports(network_id=private_net_ID_iperf_server, device_owner='network:router_interface ')['ports'][0]['device_id']

            if private_net_ID_iperf_server_router:
               public_net_ID_iperf_server = neutron_client.list_routers(id=private_net_ID_iperf_server_router)['routers'][0]['external_gateway_info']['network_id']

            logger.info("iperf client public net: %s" % public_net_ID_iperf_client)
            logger.info("iperf server public net: %s" % public_net_ID_iperf_server)
      
            thorfi_stack_params = [
                                        {
                                                  'private_net_ID_iperf_client' : private_net_ID_iperf_client,
                                                  'private_subnet_ID_iperf_client' : private_subnet_ID_iperf_client,
                                                  'public_net_ID_iperf_client' : public_net_ID_iperf_client
                                        }, 
                                        {
                                                  'private_net_ID_iperf_server' : private_net_ID_iperf_server,
                                                  'private_subnet_ID_iperf_server' : private_subnet_ID_iperf_server,
                                                  'public_net_ID_iperf_server' : public_net_ID_iperf_server
                                                                        
                                        }
                                    ]


            

            #get params specifically for the workload. For iperf workload we need, server port, bandwidth, protocol params
            workload_params = { 
                                'iperf_server_port' : request.form['iperf_server_port'],
                                'iperf_bandwidth' : request.form['iperf_bandwidth'],
                                'iperf_protocol' : request.form['iperf_protocol']
                              }

        elif 'jmeter' in workload_type:
            private_net_ID_jmeter_client= request.form['private_net_ID_jmeter_client']
            private_subnet_ID_jmeter_client = request.form['private_subnet_ID_jmeter_client']

            private_net_ID_jmeter_client_router = neutron_client.list_ports(network_id=private_net_ID_jmeter_client, device_owner='network:router_interface ')['ports'][0]['device_id']
            public_net_ID_jmeter_client = neutron_client.list_routers(id=private_net_ID_jmeter_client_router)['routers'][0]['external_gateway_info']['network_id']

            logger.info("jmeter client public net: %s" % public_net_ID_jmeter_client)

            thorfi_stack_params =  [
                                                {
                                                    'private_net_ID_jmeter_client' : private_net_ID_jmeter_client,
                                                    'private_subnet_ID_jmeter_client' : private_subnet_ID_jmeter_client,
                                                    'public_net_ID_jmeter_client' : public_net_ID_jmeter_client
                                                }
                                    ]
            #TODO: add file.jmx if the user has uploaded it                        
            
            workload_params = {
                                'jmeter_server_ip' : request.form['jmeter_server_ip'],
                                'jmeter_server_port' : request.form['jmeter_server_port'],
                                'jmeter_page_file_path': request.form['jmeter_page_file_path'],
                                'jmeter_http_method': request.form['jmeter_http_method'],
                                'jmeter_connection_timeout': request.form['jmeter_connection_timeout'],
                                'jmeter_response_timeout' : request.form['jmeter_response_timeout'],
                                'jmeter_troughput_value' : request.form['jmeter_troughput_value']
                           }

          

    logger.info("Starting deploying workload instances for the workload type: '%s'" % workload_type)

    try:

        thorfiAgent = getObjectRef(current_user.agent_ref)
        glance_client = thorfiAgent.getGlanceClientAuth()
        
        thorfi_image_name = current_app.config['THORFI_OPENSTACK_IMAGE_NAME']
        thorfi_image_path = thorfiAgent.getThorFIappDirPath() + '/' + current_app.config['THORFI_OPENSTACK_QCOW2_IMAGE_FILE']

        thorfi_image = get_thorfi_image(glance_client, thorfi_image_name)

        logger.info("thorfi_image_name: %s thorfi_image is : %s" % (thorfi_image_name, thorfi_image))

        if not thorfi_image:
            
            logger.debug("Image '%s' does not exist on current OpenStack testbed...create it using image file %s" % (thorfi_image_name, thorfi_image_path))
            thorfi_image = create_thorfi_image(glance_client, thorfi_image_name, thorfi_image_path)

        logger.debug("Image 'thorfi_image' ref: %s" % thorfi_image)


        #deploy instances accoding to workload type
        thorfiAgent = getObjectRef(current_user.agent_ref)

        heat_client = thorfiAgent.getHeatClientAuth()

        thorfi_stack_name =  'thorfi_' + workload_type + '_stack_' + current_user.user_signature
        thorfi_flavor_name = current_app.config['THORFI_OPENSTACK_FLAVOR_NAME']

        stack_ref = None
        thorfi_stack_status = None
        thorfi_stack_id = None

        for stack in heat_client.stacks.list():
            
            #check if workload stack already exists in the OpenStack testbed
            if stack.stack_name in thorfi_stack_name:
                logger.info("Workload stack '%s' of type %s is already deployed" % (thorfi_stack_name, workload_type))
                stack_ref = stack
                break

        thorfi_stack_template = thorfiAgent.getThorFIappDirPath() + '/' + workload_type + '.yaml'
        
        thorfiAgent = getObjectRef(current_user.agent_ref)

        nova_client = thorfiAgent.getNovaClientAuth()

        if not stack_ref:

            #deploy 'workload_type' stack
            logger.info("Creating workload stack '%s' of type %s with template %s" % (thorfi_stack_name, workload_type, thorfi_stack_template))
            
            #check if flavor 'thorfi_flavor' exists
            if not check_thorfi_flavor(nova_client, thorfi_flavor_name):
                logger.info("ThorFI flavor '%s' does not exists...create it" % thorfi_flavor_name)
                #create it...2 vCPU, 1Gb RAM, 3Gb Disk
                thorfi_flavor = nova_client.flavors.create(thorfi_flavor_name, 
                                                            current_app.config['THORFI_OPENSTACK_FLAVOR_RAM'],
                                                            current_app.config['THORFI_OPENSTACK_FLAVOR_VCPU'],
                                                            current_app.config['THORFI_OPENSTACK_FLAVOR_DISK'])

                logger.info("ThorFI flavor '%s' created successfully (%s)" % (thorfi_flavor_name, thorfi_flavor))

            #merge list of params in thorfi_stack_params
            thorfi_stack_params_merged = {}
            for el in thorfi_stack_params:
                for k,v in el.items():
                    thorfi_stack_params_merged.update(el)

            #thorfi_stack_params_merged['image'] = thorfi_image_name
            
            logger.debug("ThorFI stack params is: %s" % thorfi_stack_params_merged)
  
            #create 'thorfi_stack_name' stack
            stack_ref = create_thorfi_stack(heat_client, thorfi_stack_name, thorfi_stack_template, thorfi_stack_params_merged)
            
            logger.info("Check for ThorFI stack creation completion...")
            thorfi_stack_status = check_thorfi_stack_status(heat_client, stack_ref['stack']['id'], 'CREATE_COMPLETE')
     
        #if thorfi_stack already exists we need to update virtual networks for already deployed instances
        else:

            #for each el in thorfi_stack_params update stack
            for params in thorfi_stack_params:
                
                curr_param = ''

                for k,v in params.items():
                    if 'iperf_client' in k:
                        curr_param = 'iperf_client'
                        curr_vm = '__ThorFI_iperf_client'
                    elif 'iperf_server' in k:
                        curr_param = 'iperf_server'
                        curr_vm = '__ThorFI_iperf_server'
                    elif 'jmeter_client' in k:
                        curr_param = 'jmeter_client'
                        curr_vm = '__ThorFI_jmeter_client'

                logger.info("Updating stack '%s' (ID: %s) with new parameters %s" % (thorfi_stack_name, stack_ref.id, params))

                #params['image'] = thorfi_image_name

                update_thorfi_stack(heat_client, stack_ref.id, thorfi_stack_name, thorfi_stack_template, params) 
            
                logger.info("Check for ThorFI stack update completion...")
                thorfi_stack_status = check_thorfi_stack_status(heat_client, stack_ref.id, 'UPDATE_COMPLETE')
                sleep(10)
 
                stack_outputs= heat_client.stacks.get(stack_ref.id).outputs
                logger.info("stack_outputs :> %s" % stack_outputs)

                public_ip = ''

                logger.debug("Get public ip from workload instances...curr_param: %s" % curr_param)

                if 'iperf' in workload_type:

                    if 'server' in curr_param:
                        public_ip = get_iperf_instances_ips(stack_outputs, 'iperf_server_public_ip')
                    else:
                        public_ip = get_iperf_instances_ips(stack_outputs, 'iperf_client_public_ip')

                elif 'jmeter' in workload_type:
                    
                    public_ip = get_iperf_instances_ips(stack_outputs, 'jmeter_client_public_ip')

                #check if VM are booted, in case just boot it
                vm_obj = nova_client.servers.list(search_opts={'name' : curr_vm})
                if not 'ACTIVE' in vm_obj[0].status:
                    logger.warning("VM '%s' is shutoff...start it!" % curr_vm)
                    vm_obj[0].start()

                logger.info("Check reachability of public_ip %s" % public_ip)
                check_instances_reachability([public_ip], 120)

        if isinstance(stack_ref, dict):
            # stack is freshly created
            thorfi_stack_id = stack_ref['stack']['id']
        else:
            # stack already exists and it is updated
            thorfi_stack_id = stack_ref.id

        if not thorfi_stack_status:
            thorfi_stack_status = stack_ref.stack_status

        logger.debug("ThorFI workload stack details:")
        logger.debug("...............................name: %s" % thorfi_stack_name)
        logger.debug("...............................reference: %s" % stack_ref)
        logger.debug("...............................stack_status: %s" % thorfi_stack_status)

        #save stack ID, workload type, and workload params, to execute workload on it later
        '''
        thorfiWorkload = ThorFIWorkload(
                                            logger, 
                                            workload_type, 
                                            workload_params,  
                                            thorfi_stack_id,
                                            heat_client.stacks.get(thorfi_stack_id).outputs,
                                            thorfiAgent.getThorFIappDirPath() + '/thorfi.key'
                                          )
        '''

        logger.info("LOG FILE PATH: %s" % thorfiAgent.getThorFILogFileName())
        thorfiWorkload = ThorFIWorkload(
                                            thorfi_log_file=thorfiAgent.getThorFILogFileName(),
                                            workload_type=workload_type,
                                            workload_params=workload_params,  
                                            thorfi_stack_id=thorfi_stack_id,
                                            thorfi_stack_outputs=heat_client.stacks.get(thorfi_stack_id).outputs,
                                            thorfi_key_path=thorfiAgent.getThorFIappDirPath() + '/thorfi.key'
                                          )
 
        thorfiAgent.setThorFIWorkloadRef(thorfiWorkload)

        #we need to refresh pickled object
        refreshed_agent_ref = pickle.dumps(thorfiAgent)
        update_user_agent_ref(current_user.user_signature, refreshed_agent_ref)


        return "OK"

    except Exception as ex:

        logger.error("Exceptions during deploying of thorfi workload instances!")
        logger.error("Raised exception %s" % ex)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)
        abort(501)
    


@thorfi.route('/serverslist', methods=['GET'])
def serverslist():

  thorfiAgent = getObjectRef(current_user.agent_ref)
  #get nova client
  nova_cli = thorfiAgent.getNovaClientAuth()
  #get list of servers
  servers_obj = nova_cli.servers.list(detailed=True)  
  

  servers = {}
  servers['servers'] = []

  for server in servers_obj:
    servers['servers'].append(server.to_dict())

  return json.dumps(servers)


@thorfi.route('/getWorkloadType', methods=['POST'])
def getWorkloadType():

  thorfiAgent = getObjectRef(current_user.agent_ref)

  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  try:
    with open(campaign_path + '/workload_type.json', 'r') as file:
      workload_type = json.loads(file.read())
  except IOError as e:
      abort(404)

  return json.dumps(workload_type)



@thorfi.route('/stop_tests', methods=['POST'])
def stop_tests():
 
  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  logger.info("ThorFI test cases execution STOPPING. Waiting for the termination of the current test...")
  
  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  resp = {}
 
  try:
    with open(campaign_path + '/fips_status.txt', 'r') as file:
      filedata = file.readlines()

    for index in range(0, len(filedata)):

      if filedata[index].strip().split('#')[1] == 'inProgress':

        #if the current test is not the last
        if index != len(filedata) - 1:

          filedata[index+1] = str(index + 2) + '#stopped\n'

          with open(campaign_path + '/fips_status.txt', 'w') as file:
            file.writelines(filedata)
      
          resp['test'] = 'stopped'

        #if the current test is the last
        else:

          resp['test'] = 'all'

        break

    logger.info("ThorFI test cases execution STOPPED. Waiting for the termination of the current test...")     

    return json.dumps(resp)

  except IOError as e:
    logger.warning("An error occurs during stop_tests execution!!!")
    abort(404)

  except Exception as err:
    logger.warning("An error occurs during stop_tests execution!!!")
    logger.warning("Exception raised %s" % err)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=30, file=sys.stdout)
    abort(501)


@thorfi.route('/getStoppedTestCases', methods=['POST'])
def getStoppedTestCases():

  """
      getStoppedTestCases function read from ThorFI db the status of tests in the fip_list and check
      the status transition from 'stopped' to 'NotCompleted' for a test, if the stop routine is called.
      The user can press Stop button only once, so at most one test can go into the stopped state. In the start_tests
      loop this stopped condition is checked and before exiting the loop, the stopped test status is changed to NotComplted.
      Therefore, no test will have a stopped status and this condition is used to determine that the last test executed is terminated 
      and the thorfi execution can be interrupted.
  """
  thorfiAgent = getObjectRef(current_user.agent_ref)
  logger = get_thorfi_app_logger(thorfiAgent)

  #logger.info("Waiting for the termination of the current test...")

  current_campaign_name = request.form['campaign_name']
  campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
  campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name

  try:

    with open(campaign_path + '/fips_status.txt', 'r') as file:
      filedata = file.readlines()

    for fip in filedata:

      if fip.strip().split('#')[1] == 'stopped':

        return json.dumps({'status' : 'false'})
            
    return json.dumps({'status' : 'true'})

  except IOError as e:
    logger.warning("An error occurs during getStoppedTestCases execution!!!")
    abort(404)

  except Exception as err:
    logger.warning("An error occurs during getStoppedTestCases execution!!!")
    logger.warning("Exception raised %s" % err)
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_tb(exc_traceback, limit=30, file=sys.stdout)
    abort(501)



@thorfi.route('/start_tests', methods=['POST'])
def start_tests():

    """
      start_tests function read from ThorFI db the list of tests to execute for the specific user
      and checks for each test if it is in a 'completed' state; if not it executes the test by calling 
      'inject_XXX' function according to the test
    """
    
    thorfiAgent = getObjectRef(current_user.agent_ref)
    flush_thorfi_log(thorfiAgent)

    logger = get_thorfi_app_logger(thorfiAgent)

    #TODO: enable start_tests API to be called by thorfi_client.py

    #get injection time parameters from dashboard
    pre_injection_time = request.form['pre_injection_time']
    injection_time = request.form['injection_time']
    post_injection_time = request.form['post_injection_time']

    injector_time_params = { 'pre_injection_time': pre_injection_time, 'injection_time': injection_time, 'post_injection_time': post_injection_time}


    #TODO: for the DEMO we read from 'user'_fips_list.txt the test list and update accordingly the status in 'user'_fips_status.txt
    #      Instead, we NEED to access the ThorFI DB for the status of the campaign

    current_campaign_name = request.form['campaign_name']
    campaign_name = 'Campaigns/' + current_user.user_signature + '/campaign_' + current_campaign_name
    campaign_path = thorfiAgent.getThorFIappDirPath() + '/' + campaign_name
  
    campaign_id = getCampaignID(current_user.user_signature, current_campaign_name)

    #save injector_time_param in injection_setup.json file 
    try:
      with open(campaign_path + '/injection_setup.json', 'w') as file:
        json.dump(injector_time_params, file)
    except IOError as e:
        abort(501)

    thorfiWorkload = thorfiAgent.getThorFIWorkloadRef()

    #save workload_type in workload_type.json file
    workload_type_params = {'workload_type' : thorfiWorkload.getThorFIWorkloadType()}
    try:
      with open(campaign_path + '/workload_type.json', 'w') as file:
        json.dump(workload_type_params, file)
    except IOError as e:
        abort(501)

    # get number of fips list
    fips_list_len = len(open(campaign_path + '/fips_list.txt').readlines()) 
    
    # create test list in memory
    tests = []
    with open (campaign_path + '/fips_list.txt', 'r') as fips_list:
        for test in fips_list:
            cur_test = test.strip().split('#')
            tests.append(cur_test)

    for current_test_index in range(1, fips_list_len+1):


        #check if the status of current test is "stopped". In this case stopping execution of tests
        with open(campaign_path + '/fips_status.txt', 'r') as fips_status:    
          test_status = fips_status.readlines()

        if test_status[current_test_index-1].strip().split('#')[1] == 'stopped':
          
          test_status[current_test_index-1] = str(current_test_index) + '#' + 'NotCompleted\n'

          with open(campaign_path + '/fips_status.txt', 'w') as file:
            file.writelines(test_status) 

          #exit start_tests loop. The subsequent tests in the list will be skipped  
          break

        #while line_test:

        # parse 'line_test' into paramters for injecting fault
        #id_test, domain, type_resource, name_resource, target_fault, fault_type, arg, description
        #1,tenant,network,tenant2-network,tenant2-network,delay,1000,Tenant network experiences packet delay.

        if test_status[current_test_index-1].strip().split('#')[1] == 'NotCompleted':

              test = tests[current_test_index-1]

              logger.info("Execute test ID: %s TEST: %s" % (current_test_index, test))
              resource_type = test[2]

              if resource_type == "interface":
                target_resource_id = {}
                target_resource_id.setdefault(test[4],test[3])
              else:
                target_resource_id = test[4]

              fault_type = test[5]

              #check fault args based on 'fault_type'

              if 'latency' in fault_type:
                  fault_type = 'delay'
                  fault_args = test[6] + 'ms'
              elif 'corrupt' or 'loss' or 'duplicate' in fault_type:
                  fault_args = test[6] + '%'

              # description is test[7]

              fault_pattern = test[8]
              fault_pattern_args = [test[9], test[10]]
              fault_target_traffic = test[11]
              fault_target_protocol = test[12]
              fault_target_dst_ports = test[13].split(';')
              fault_target_src_ports = test[14].split(';')


              test_status[current_test_index-1] = str(current_test_index) + '#' + 'inProgress\n'

              with open(campaign_path + '/fips_status.txt', 'w') as fips_status:
                fips_status.writelines(test_status)

              # call inject function call according to test parameters
              thorfiWorkload = thorfiAgent.getThorFIWorkloadRef()

              try:

                    if current_user.urole == "virtual":
                      #paranoic check. stop any workload running before
                      thorfiWorkload.stop_thorfi_workload(logger)
                      
                      #prepare thorfi instances (e.g., flush logs etc.)
              
                      thorfiWorkload.prepare_thorfi_workload_instances(logger)

                      thorfiWorkload.start_thorfi_workload(logger)

                    else:
                      #paranoic check. stop any workload running before
                      thorfiWorkload.stop_thorfi_workload_phy(logger)
                      
                      #prepare thorfi instances (e.g., flush logs etc.)
              
                      thorfiWorkload.prepare_thorfi_workload_instances_phy(logger)

                      thorfiWorkload.start_thorfi_workload_phy(logger)              

                    workload_timeout = float(injector_time_params['pre_injection_time']) + float(injector_time_params['injection_time']) + float(injector_time_params['post_injection_time'])
                    logger.info("The workload will last for %s s" % workload_timeout)

                    #schedule thread that actually wait before stopping the started workload
                    thorfi_workload_completion_thread = ThorFIWorkloadThread(thorfiWorkload.wait_for_thorfi_workload_completion, workload_timeout)
                    thorfi_workload_completion_thread.start()

                    # get ref to 'inject_XXX' through globals() call and perform injection
                    logger.info("Injection will start in %s s" % injector_time_params['pre_injection_time'])
                    logger.info("Injection will last for %s s" % injector_time_params['injection_time'])
                    logger.info("After injection we will wait %s s before saving workload logs" % injector_time_params['post_injection_time'])

                    ret = globals()['inject_' + resource_type](
                                                                target_resource_id, 
                                                                fault_type, 
                                                                fault_args, 
                                                                fault_pattern, 
                                                                fault_pattern_args, 
                                                                fault_target_traffic, 
                                                                fault_target_protocol, 
                                                                fault_target_dst_ports, 
                                                                fault_target_src_ports, 
                                                                injector_time_params
                                                              )

                    logger.info("Injection ends. RET: %s" % ret)
                    

                    # wait for workload completion
                    thorfi_workload_completion_thread.join()
                    logger.info("ThorFI Workload timeout (%s s) reached." % workload_timeout)
                    
                    # stop thorfi workload
                    if current_user.urole == "virtual":
                      thorfiWorkload.stop_thorfi_workload(logger) 
                    else:
                      thorfiWorkload.stop_thorfi_workload_phy(logger) 

                    # after workload completion save logs
                    test_dir = campaign_path + '/Test_' + str(current_test_index)
         
                    if current_user.urole == "virtual":
                      thorfiWorkload.save_logs(current_test_index, test_dir, logger)
                    else:
                      thorfiWorkload.save_logs_phy(current_test_index, test_dir, logger)

                     
                    #check if fault type is delete, then properly update the fips list
                    logger.info("ret %s" % ret)
                    if ret and 'delete' in fault_type:
                        logger.debug("Update fips list according to restored resources!")
                          
                        for restored_el in ret:

                              for test in tests:

                                  for old,new in restored_el.items():
                                          
                                      if old in test[4]:
                                          test[4] = new
                                          logger.debug("new fip is %s" % test)

                              logger.debug("Updated fips list!!!")

              except Exception as ex:

                    #set test status to 'error'
                    logger.warning("Test '%s' results in error during injection" % test)
                    logger.warning("Exception raised %s" % ex)
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    traceback.print_tb(exc_traceback, limit=30, file=sys.stdout)

                    with open(campaign_path + '/fips_status.txt', 'r') as fips_status:
                        test_status = fips_status.readlines()
                    
                    test_status[current_test_index-1] = str(current_test_index) + '#' + 'error\n'

                    with open(campaign_path + '/fips_status.txt', 'w') as fips_status:
                        fips_status.writelines(test_status)

                    updateTestStatus(campaign_id, current_test_index, status="error")
                        
                    continue

              # when test is finished set status to completed in 'user'_fips_status.txt 
              with open(campaign_path + '/fips_status.txt', 'r') as fips_status:
                  test_status = fips_status.readlines()
              
              if ret in 'SKIP':
                  status = 'skipped'
              else:
                  status = 'completed'

              test_status[current_test_index-1] = str(current_test_index) + '#' + status + '\n'

              with open(campaign_path + '/fips_status.txt', 'w') as fips_status:
                  fips_status.writelines(test_status)

              updateTestStatus(campaign_id, current_test_index, status=status)
          
              logger.info("Test ID %s completed!" % current_test_index)

        else:

          logger.info("Test ID: %s TEST: %s SKIPPED because it is in %s status" % (current_test_index, tests[current_test_index-1], test_status[current_test_index-1].strip().split('#')[1]))

    logger.info("All tests are completed")

    return "OK"

@thorfi.route('/getInstancesConsoles', methods=['GET'])
def getInstancesConsoles():

    """
        getInstancesConsoles API return novnc links to dashboard in order to open vnc console
        E.g.:
          {
            'vm1':'http://10.0.20.200:6080/vnc_auto.html?token=d002ee36-ff45-490b-8739-39a2b545ba5e',
            'vm2':'http://10.0.20.200:6080/vnc_auto.html?token=d002ee36-ff45-490b-8739-39a2basdd05e',
            ...
          }
    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)


    nova_client = thorfiAgent.getNovaClientAuth()
    instance_consoles = {}
    for instance in nova_client.servers.list():
        logger.info("instance: %s" % instance)
        try:
          instance_consoles[instance.name] = instance.get_vnc_console('novnc')['console']['url']
        except Exception as ex:
          instance_consoles[instance.name] = ""
          logger.warning("Instance '%s' results in error state" % instance)
          logger.warning("Exception raised %s" % ex)
          continue
            
    logger.info("instance: %s" % instance_consoles)

    return json.dumps(instance_consoles)

#Read log file and send to the front-end
@thorfi.route('/getThorFILogs', methods=['GET'])
def getThorFILogs():

    try:
            thorfiAgent = getObjectRef(current_user.agent_ref)

            with open(thorfiAgent.getThorFILogFileName(), 'r') as f:
                    return json.dumps(f.read())
    except IOError:
            return json.dumps("waiting for ThorFI log")



def do_injection_thorfi_item(thorfi_item_map, fault_target_traffic, fault_target_protocol, fault_target_dst_ports, fault_target_src_ports, fault_type, fault_args, injector_time_params, fault_pattern=None, fault_pattern_args=None, target_name=None):

    """
        We need to iterate over port list and differentiate injection based on the port type:
    
        compute:nova: in that case, the port is related to a virtual interface of a specific instance.
                      The injection procedure include injecting fault at tap interface. The tap interface ID
                      is identified by the first 11 chars of the port ID string. E.g.:
        
                          PORT_ID: 0db8a25d-4c9f-4f81-b9e9-84a5b189a939 => TAP device ID: 0db8a25d-4c
        
                      Once we obtain TAP device_id, we sent command to host_id to drop, delay, or corrupt
                      traffic on that inteface.
     
        network:router_interface: in that case the port is related to a virtual interface towards tenant networks.
                                  The injection procedure include injecting fault at qr-XXX interfaces.
    
        network:router_gateway: in that case the port is related to a virtual interface towards public internet
                                The injection procedure include injecting fault at qg-XXX interfaces.

        network:dhcp: in that case the port is related to a virtual dhcp service.
                      THe injection procedure include injecting fault at linked tap interface.

        network:floatingip: in that case the port is related to a floating ip.
                            The injection procedure include the specific qg-XXX interfaces that
                            belongs to IP subnet that handle a specific virtual router. Thus, we need to specify
                            the corret network namespace (related to the router), the qg-XXX device, and the floating IP
                            
    """


    # for each port we get the host_id binding and generate the proper injection command to be sent to agent
    # listening on host_id ip
  
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    logger.info("Start do_injection_thorfi_item!")

    # map between host_id and port
    host_port_map = {}

    for port_id, thorfi_item in thorfi_item_map.items():
     
        logger.debug("Iterate over: " % thorfi_item_map.items())

        # map between current port and netns if it exists
        target_device_netns_map = {}

        host_id = thorfi_item['binding:host_id']
        device_id = thorfi_item['id'][0:11]

        netns = ''
        target_device = ''

        if thorfi_item['device_owner'] in 'compute:nova':

            target_device = 'tap' + device_id
             
        # if the target is a virtual router we need to save info about network namespace
        elif thorfi_item['device_owner'] in 'network:router_interface':

            netns = 'qrouter-' + thorfi_item['device_id']
            target_device = 'qr-' + device_id

        # if the target is a virtual router we need to save info about network namespace (i.e., qrouter-XXX-XXX)
        elif thorfi_item['device_owner'] in 'network:router_gateway':

            netns = 'qrouter-' + thorfi_item['device_id']
            target_device = 'qg-' + device_id

        # if the target is a virtual dhcp we need to save info about network namespace (i.e., qdhcp-XXX-XXX)
        elif thorfi_item['device_owner'] in 'network:dhcp':
            
            netns = 'qdhcp-' + thorfi_item['network_id']
            target_device = 'tap' + device_id

        elif thorfi_item['device_owner'] in 'network:floatingip':

            # TODO: handle floating_ip ports.
            #       netns is related to router namespace in which exists the float IP
            #       target_device is the qg-XXX interface os such router.

            #netns = ''
            #target_device = ''
            target_fip = str(thorfi_item['fixed_ips'][0]['ip_address'])
            inject_floatingip(target_fip, fault_type, fault_args, injector_time_params)
            return 


        if target_device:
            # create target device list to be passed to injector agent

            target_device_netns_map [target_device] = netns
            host_port_map.setdefault(host_id, []).append(target_device_netns_map)

        else:
            #raise ThorFIDeviceOwnerNotSupported(thorfi_item['device_owner'])
            logger.warning("Device owner '%s' not supported for the injection...skip the port!" % (thorfi_item['device_owner']))
            continue
     
        # call injector agent 'inject' API to inject the fault for each host in host_port_map

        logger.debug("host_port_map %s" % host_port_map)
        logger.debug("target_device_netns_map %s" % target_device_netns_map)
    
    injector_pool = Pool()

    global host_down

    # for each host in host_port_map send a request to inject
    for host_ip, device_netns_map in host_port_map.items():
    
        if host_down and host_ip in host_down:
            
            return "SKIP"

        fault_configuration = {'nics': device_netns_map,
                                'fault_target_traffic' : fault_target_traffic, 
                                'fault_target_protocol' : fault_target_protocol,
                                'fault_target_dst_ports' : fault_target_dst_ports,
                                'fault_target_src_ports' : fault_target_src_ports,
                                'fault_type': fault_type,
                                'fault_pattern': fault_pattern,
                                'fault_args': fault_args,
                                'fault_pattern_args' : fault_pattern_args,
                                'pre_injection_time': injector_time_params['pre_injection_time'],
                                'injection_time': injector_time_params['injection_time'],
                                'post_injection_time': injector_time_params['post_injection_time'],
                                'target_name': target_name}


        injector_pool.apply_async(make_post_inject, args = (host_ip, fault_configuration))

    injector_pool.close()
    injector_pool.join()

    return "OK"


def print_response(req, *args, **kwargs):
  
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)
    logger.debug("Request to injector agent URL: %s ; RESPONSE: %s" % (req.url, req.text))

#@asyncio.coroutine
def make_post_inject(host_ip, fault_configuration):

    """
        This method actually send to injector agent on 'host_ip' the injection command
        specified by 'fault_configuration' arg. We call the '/inject' API on injector agent


    Args:
        host_ip: IP or host name where is running the injector agent
        fault_configuration: the configuration of injection that must be sent to injector agent 
                             to perform injection
    Raises:
        requests.exceptions.ConnectionError: if there is some problem to communicate with injector agent

    """
    default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)


    # make_post_inject actually send request to injector agent
    try:
        logger.debug("Send request to inject at %s with fault configuration => %s " % (host_ip, fault_configuration))

        #TODO: create request id to link with response
        
        #if 'localhost.localdomain' in host_ip:
        #    host_ip = 'localhost'

        req_to_inject = requests.post('http://' + host_ip + ':' + default_injector_port + '/inject', json=fault_configuration, hooks=dict(response=print_response))

        #if fault type is 'delete' we need to return the changed resources by dict {'old_id':'new_id'}
        if 'delete' in fault_configuration['fault_type']:
            return json.loads(req_to_inject.text)

    except requests.exceptions.ConnectionError as e:

        #TODO: for now we avoid to contact node in which injector agent is not started,
        #      but we need to stop the test actually

        logger.warning("Impossible to reach injector agent on node: %s...skip it" % host_ip)
        pass

def get_thorfi_item_list(neutron_cli, id_type, target_resource_id):

    """
        Method return the thorfi_item_map, i.e., the {port['id'] : port } dict for the specified target_resource_id and id_type.
        Such thorfi_item_map is populated matching the target_resource_id the thorfi_item (in OpenStack the port) belong.
        thorfi_item_map is passed to do_injection_thorfi_item for injecting in each specified thorfi_item

    Args:
      neutron_cli: neutron client object reference

      id_type: can be 'network_id' to specifiy network (used for network resource injection), 
                or 'device_id' to specify a device (used for router resource injection)

      target_resource_id: is the id for the target resource. 
                          It is used to understand if port belong to the target resource
  
    Return:
      thorfi_item_map: dict that maps {port['id'] : port }

    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)


    # get port list
    port_list = neutron_cli.list_ports()
    thorfi_item_map = {}

    # for each port in the target network, inject!
    for port in port_list['ports']:

        logger.debug("id_type: %s" % id_type)
        logger.debug("PORT_ID: %s device_owner: %s device_id: %s port[id_type]: %s host_id: %s" % (port['id'], port['device_owner'], port['device_id'], port[id_type], port['binding:host_id']))
        
        if 'fixed_ips' in id_type and port[id_type][0]['subnet_id'] in target_resource_id:
                
            thorfi_item_map[port['id']] = port

        elif 'fixed_ips' not in id_type and port[id_type] in target_resource_id:

            thorfi_item_map[port['id']] = port


    return thorfi_item_map

def get_thorfi_fault_configuration(logger, content, injector_time_params):
    
    if content:
        logger.debug("Received data %s" % content)

        target_resource_id = content['target_resource_name']
        fault_type = content['fault_type']
        fault_args = content['fault_args']

        fault_pattern = content.get('fault_pattern', None)
        fault_pattern_args = content.get('fault_pattern_args', None)
        #if fault_pattern_args:
        #fault_pattern_args = json.loads(fault_pattern_args)
        if fault_pattern_args is not None:
            fault_pattern_args = fault_pattern_args.split(';')

        fault_target_traffic = content.get('fault_target_traffic', 'any')
        fault_target_protocol = content.get('fault_target_protocol', None)
        
        fault_target_dst_ports = content.get('fault_target_dst_ports', None)

        #if fault_target_dst_ports:
        #fault_target_dst_ports = json.loads(fault_target_dst_ports)
        if fault_target_dst_ports is not None:
            fault_target_dst_ports = fault_target_dst_ports.split(';')
      
        fault_target_src_ports = content.get('fault_target_src_ports', None)

        #if fault_target_src_ports:
        #fault_target_src_ports = json.loads(fault_target_src_ports)
        if fault_target_src_ports is not None:
            fault_target_src_ports = fault_target_src_ports.split(';')

    else:

        logger.debug("We are calling API as function call and not as POST request!")

    if not injector_time_params:
        pre_injection_time = content['pre_injection_time']
        injection_time = content['injection_time']
        post_injection_time = content['post_injection_time']
        injector_time_params = {'pre_injection_time': pre_injection_time, 'injection_time': injection_time, 'post_injection_time' : post_injection_time}
    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

    logger.info("Fault injection configuration:")
    
    logger.info("..............................target_resource_id: %s" % target_resource_id)
    
    logger.info("..............................fault_pattern: %s" % fault_pattern)
    logger.info("..............................fault_pattern_args: %s" % fault_pattern_args)
    
    logger.info("..............................fault_target_traffic: %s" % fault_target_traffic)
    logger.info("..............................fault_target_protocol: %s" % fault_target_protocol)
    logger.info("..............................fault_target_dst_ports: %s" % fault_target_dst_ports)
    logger.info("..............................fault_target_src_ports: %s" % fault_target_src_ports)

    logger.info("..............................fault_type: %s" % fault_type)
    logger.info("..............................fault_args: %s" % fault_args)
    logger.info("..............................pre_injection_time: %s s" % pre_injection_time)
    logger.info("..............................injection_time: %s s" % injection_time)
    logger.info("..............................post_injection_time: %s s" % post_injection_time)

    return target_resource_id, \
            fault_pattern, \
            fault_pattern_args, \
            fault_target_traffic, \
            fault_target_protocol, \
            fault_target_dst_ports, \
            fault_target_src_ports, \
            fault_type, \
            fault_args, \
            pre_injection_time, \
            injection_time, \
            post_injection_time, \
            injector_time_params


@thorfi.route('/inject_network', methods=['POST'])
#def inject_network(target_network_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, injector_time_params=None):
def inject_network(target_network_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):
    
    """
        API for injecting faults into resource 'network' of neutron
        We perform injection for each port linked to the given network name
    
    POST data:
        target_network_id: is the ID of the target network
        fault type: is the fault type to be inject
        fault_pattern: is the fault pattern to be injected (i.e., Random, Burst, Degradation, Persistent)
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    Raises:
        ThorFINetworkNotFoundException: if a network resource is not found
    """
   
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    target_type = 'network'

    # get request for injecting in 'network' resource from thorfi client

    content = request.get_json()

    if content:
        target_network_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)
    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

    logger.info("..............................target_type: %s" % target_type)
    # get reference for neutron client
    thorfiAgent = getObjectRef(current_user.agent_ref)

    neutron_cli = thorfiAgent.getNeutronClientAuth()

    if target_network_id:

        #NOTE: if the fault type is the deletion of a network resource we make a POST to injector agent on localhost (the controller)
        if 'delete' in fault_type:

            fault_configuration = {'client_auth' : thorfiAgent.getClientAuth(),
                                    'nics': '',
                                    'fault_type': fault_type,
                                    'fault_args': fault_args,
                                    'pre_injection_time': pre_injection_time,
                                    'injection_time': injection_time,
                                    'post_injection_time': post_injection_time,
                                    'target_name': target_network_id,
                                    'target_type': target_type
                                  }

            resource_old_new = make_post_inject('localhost', fault_configuration)
            return resource_old_new
            
            
        else:

            thorfi_item_map = get_thorfi_item_list(neutron_cli, 'network_id', target_network_id)
            
            #enable injection for ports in network with 'network_id'
            ret = do_injection_thorfi_item(thorfi_item_map, fault_target_traffic, fault_target_protocol, fault_target_dst_ports, fault_target_src_ports, fault_type, fault_args, injector_time_params, fault_pattern, fault_pattern_args)

        return ret

    else:
        raise ThorFINetworkNotFoundException(target_network_id)

        return "ERROR"

@thorfi.route('/inject_floatingip', methods=['POST'])
def inject_floatingip(target_fip=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        API for injecting faults into resource 'floatingip' of neutron
        We perform injection for each port linked to the given network name
    
    POST data:
        target_fip: is the IP of the target floatingip
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    Raises:
        ThorFIFloatingIPException: if a floatingip resource is not found
    """
    
    # get request for injecting in 'network' resource from thorfi client
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    target_type = 'floatingip'

    content = request.get_json()

    if content:
        target_fip, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)

    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

    logger.info("..............................target_type: %s" % target_type)

    # get reference for neutron client
    thorfiAgent = getObjectRef(current_user.agent_ref)

    neutron_cli = thorfiAgent.getNeutronClientAuth()


    if 'delete' in fault_type:
        for port in neutron_client.list_ports()['ports']:
            if target_fip in port['fixed_ips'][0]['ip_address']:

                #call inject_port on port target

                inject_port(port['id'], 'delete', '', '', '', '', {'pre_injection_time' : pre_injection_time, 'injection_time': injection_time, 'post_injection_time': post_injection_time})
     

        return "OK"

    else:
        # get list of all floating ips
        float_ips = neutron_cli.list_floatingips()
        target_router_id = ''

        for fip in float_ips['floatingips']:

            if target_fip in fip['floating_ip_address']:

                target_router_id = fip['router_id']

        if target_router_id:
            thorfi_item_map = get_thorfi_item_list(neutron_cli, 'device_id', target_router_id)

            #enable injection for ports in network with 'network_id'
            do_injection_thorfi_item(thorfi_item_map, fault_target_traffic, fault_target_protocol, fault_target_dst_ports, fault_target_src_ports, fault_type, fault_args, injector_time_params, fault_pattern, fault_pattern_args, target_fip)

            return "OK"

        else:
            raise ThorFIFloatingIPException(target_fip)

            return "ERROR"



@thorfi.route('/inject_subnet', methods=['POST'])
def inject_subnet(target_subnet_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):
    
    """
        API for injecting faults into resource 'subnet' of neutron
        We perform injection for each port linked to the linked 'network' resource for the 'subnet' name
    
    POST data:
        target_subnet_id: is the name of the target subnet
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    Raises:
        ThorFISubnetNotFoundException: if a network resource is not found
    """
    
    # get request for injecting in 'network' resource from thorfi client
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    content = request.get_json()

    if content:
        
        target_subnet_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)

    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

    # get reference for neutron client
    thorfiAgent = getObjectRef(current_user.agent_ref)

    neutron_cli = thorfiAgent.getNeutronClientAuth()

    if target_subnet_id:
  
        thorfi_item_map = get_thorfi_item_list(neutron_cli, 'fixed_ips', target_subnet_id)
        
        #enable injection for ports in network with 'network_id'
        do_injection_thorfi_item(thorfi_item_map, fault_target_traffic, fault_target_protocol, fault_target_dst_ports, fault_target_src_ports, fault_type, fault_args, injector_time_params, fault_pattern, fault_pattern_args)

        return "OK"

    else:
        raise ThorFISubnetNotFoundException(target_subnet_id)

        return "ERROR"




@thorfi.route('/inject_router', methods=['POST'])
def inject_router(target_router_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        REST API for injecting faults into resource 'router' of neutron
        We perform injection for each port linked to the given router name
    
    POST data:
        target_router_id: is the name of the target router
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    Raises:
        ThorFIRouterNotFoundException: if a router resource is not found

    """

    target_type = 'router'
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    # get request for injecting in 'router' resource from thorfi client

    content = request.get_json()

    if content:
        
        target_router_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)

    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

    logger.info("..............................target_type: %s" % target_type)

    # get reference for neutron client
    thorfiAgent = getObjectRef(current_user.agent_ref)

    neutron_cli = thorfiAgent.getNeutronClientAuth()
    

    #check if target_router is in routers['routers']
    if target_router_id:

        if 'delete' in fault_type:

            fault_configuration = {'client_auth' : thorfiAgent.getClientAuth(),
                                    'nics': '',
                                    'fault_type': fault_type,
                                    'fault_args': fault_args,
                                    'pre_injection_time': pre_injection_time,
                                    'injection_time': injection_time,
                                    'post_injection_time': post_injection_time,
                                    'target_name': target_router_id,
                                    'target_type': target_type
                                  }

            resource_old_new = make_post_inject('localhost', fault_configuration)
            return resource_old_new

        else:
            thorfi_item_map = get_thorfi_item_list(neutron_cli, 'device_id', target_router_id)

            logger.debug("thorfi_item_map: %s" % thorfi_item_map)
            do_injection_thorfi_item(thorfi_item_map, fault_target_traffic, fault_target_protocol, fault_target_dst_ports, fault_target_src_ports, fault_type, fault_args, injector_time_params, fault_pattern, fault_pattern_args)

            return "OK"

    else:
        raise ThorFIRouterNotFoundException(target_router_id)
        
        return "ERROR"


@thorfi.route('/inject_port', methods=['POST'])
def inject_port(thorfi_item_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        REST API for injecting faults into resource 'port' of neutron
        We perform injection for the port specified in 'thorfi_item_id'
    
    POST data:
        thorfi_item_id: is the ID of the target port
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    Raises:
        ThorFIPortNotFoundException: if a port resource is not found

    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    # get request for injecting in 'router' resource from thorfi client

    target_type = 'port'

    content = request.get_json()

    if content:

        thorfi_item_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)
    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

        

    logger.info("..............................target_type: %s" % target_type)

    # get reference for neutron client
    thorfiAgent = getObjectRef(current_user.agent_ref)

    neutron_cli = thorfiAgent.getNeutronClientAuth()

    thorfi_item_map = {}
    port_list = neutron_cli.list_ports()

    for port in port_list['ports']:

        if port['id'] in thorfi_item_id:
            
            logger.debug("PORT_ID: %s device_owner: %s device_id: %s host_id: %s" % (port['id'], port['device_owner'], port['device_id'], port['binding:host_id']))
            thorfi_item_map[port['id']] = port

    if 'delete' in fault_type:

        fault_configuration = {'client_auth' : thorfiAgent.getClientAuth(),
                                'nics': '',
                                'fault_type': fault_type,
                                'fault_args': fault_args,
                                'pre_injection_time': pre_injection_time,
                                'injection_time': injection_time,
                                'post_injection_time': post_injection_time,
                                'target_name': thorfi_item_id,
                                'target_type': target_type
                              }

        resource_old_new = make_post_inject('localhost', fault_configuration)
        return resource_old_new


    if thorfi_item_map:

        do_injection_thorfi_item(thorfi_item_map, fault_target_traffic, fault_target_protocol, fault_target_dst_ports, fault_target_src_ports, fault_type, fault_args, injector_time_params, fault_pattern, fault_pattern_args)
        return "OK"

    else:

        raise ThorFIPortNotFoundException(thorfi_item_id)
        return "ERROR"


@thorfi.route('/authenticate_client', methods=['POST'])
def authenticate_client():

    thorfiAgent = ThorFIAgent()

    #thorfiAgent = getObjectRef(current_user.agent_ref)

    d = {}
    content = request.get_json()

    d['username'] = content['username']
    d['password'] = content['password']
    d['user_domain_name'] = content['user_domain_name']


    d['project_name'] = content['project_name']
    d['project_domain_id'] = content['user_domain_id']
    d['project_id'] = content['project_id']

    d['user_domain_id'] = content['project_domain_id']

    d['auth_url'] = current_app.config['AUTH_URL']

    urole='virtual'
    #set thorfi agent objects with current authenticated client
    '''
    user = User(username=d['username'],
                  password=d['password'],
                  user_domain_name=d['user_domain_name'],

                  project_name=d['auth_url'],
                  project_domain_id=d['project_domain_id'],
                  user_domain_id=d['user_domain_id'],

                  project_id=d['project_id'],

                  )
    '''

    agent_ref = pickle.dumps(thorfiAgent)

    # generate fingerprint for the user
    user_signature = hashlib.sha1(str(d['username']) + str(d['password']) + str(d['project_name']) + str(urole)).hexdigest() + '_' + d['username']

    user = User(  username=d['username'],
                  password=d['password'],
                  user_domain_name=d['user_domain_name'],

                  project_name=d['project_name'],
                  project_domain_id=d['project_domain_id'],
                  user_domain_id=d['user_domain_id'],

                  project_id=d['project_id'],

                  urole=urole,
                  agent_ref=agent_ref.encode('utf-8'),
                  user_signature=user_signature
                  )


    try:
        db.session.add(user)
        db.session.commit()
    except:
        pass

    flask.session['uid'] = uuid.uuid4()

    login_user(user, remember=True)

    print ("current_user obj: %s" % current_user)

    if user:
        print("Login OK for user  %s" % user.username)

    else:

        print("Authentication failed - Invalid OpenStack credentials")
        do_logout()


    thorfiAgent.setClientAuth(d)
    #thorfiAgent.setNeutronClientAuth()
    #thorfiAgent.setNovaClientAuth()
    #thorfiAgent.setGlanceClientAuth()
    #thorfiAgent.setHeatClientAuth()

    logger = get_thorfi_app_logger(thorfiAgent)

    logger.info("Client authentication...")
    logger.info("......................username: %s" % d['username'])
    logger.info("......................password: %s" % d['password'])
    logger.info("......................user_domain_name: %s" % d['user_domain_name'])

    logger.info("......................auth_url: %s" % d['auth_url'])

    logger.info("......................project_name: %s" % d['project_name'])
    logger.info("......................project_domain_id: %s" % d['project_domain_id'])
    logger.info("......................project_id: %s" % d['project_id'])

    logger.info("......................user_domain_id: %s" % d['user_domain_id'])

    logger.debug("thorfiAgent.getNeutronClientAuth() object %s " % thorfiAgent.getNeutronClientAuth())
    logger.debug("thorfiAgent.getNovaClientAuth() object %s " % thorfiAgent.getNovaClientAuth())
    logger.debug("thorfiAgent.getGlanceClientAuth() object %s " % thorfiAgent.getGlanceClientAuth())
    logger.debug("thorfiAgent.getHeatClientAuth() object %s " % thorfiAgent.getHeatClientAuth())

    #return "OK"
    return jsonify(status='ok', username=user.username)


# ThorFI API injection for infrastructure level faults

@thorfi.route('/inject_interface', methods=['POST'])
def inject_interface(target_host_nic_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        Method to inject faults at physical target node

    Args:
        target_host_nic_id: is a dict to specify host and nic target {'HOST_ID' : 'NIC_ID'}
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    # get request for injecting in 'router' resource from thorfi client

    target_type = 'nic'

    fault_configuration = {}
    target_host_id = None
    target_nic_id = None

    content = request.get_json()

    if content:

        target_host_nic_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)

    else:

        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']

    
    
    for host_id, nic_id in target_host_nic_id.items():
        target_host_id = host_id
        target_nic_id = nic_id

    fault_configuration = {
                                'nics': [{nic_id : ''}],
                                'fault_target_traffic' : fault_target_traffic, 
                                'fault_target_protocol' : fault_target_protocol,
                                'fault_target_dst_ports' : fault_target_dst_ports,
                                'fault_target_src_ports' : fault_target_src_ports,
                                'fault_type': fault_type,
                                'fault_pattern': fault_pattern,
                                'fault_args': fault_args,
                                'fault_pattern_args' : fault_pattern_args,
                                'pre_injection_time': injector_time_params['pre_injection_time'],
                                'injection_time': injector_time_params['injection_time'],
                                'post_injection_time': injector_time_params['post_injection_time'],
                                'target_name': ''
                              }
                    

    logger.info("Fault configuration:")
    logger.info(fault_configuration)
    logger.info("..............................target_type: %s" % target_type)


    default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']

    
    # make_post_inject actually send request to injector agent
    try:    
             
        if host_down and target_host_id in host_down:

            return "SKIP"
        else:

            make_post_inject(target_host_id, fault_configuration)

        
    except requests.exceptions.ConnectionError as e:

        #TODO: for now we avoid to contact node in which injector agent is not started,
        #      but we need to stop the test actually

        logger.warning("Impossible to reach injector agent on node: %s...skip it" % target_node_id)
        pass 

    return "OK"

@thorfi.route('/inject_switch', methods=['POST'])
def inject_switch(target_switch_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        Method to inject faults at physical target node

    Args:
        target_switch_id: is the target switch ID
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    # get request for injecting in 'router' resource from thorfi client

    target_type = 'switch'

    content = request.get_json()

    if content:

        target_switch_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)
    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']
        

    logger.info("..............................target_type: %s" % target_type)


    default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']

    global phy_network_topology
  
    #obtain all the NICs linked to the host attached to the target switch
    #phy_network_topology = thorfiAgent.getPhyNetworkTopology() 

    injector_pool = Pool() 

    for node in phy_network_topology['nodes']:

      if node['group'] == 7:
            
          if node['ID'] in target_switch_id:
               
                for port_id, info in node['fault_target_advanced'].items():

                    for target in info:
                        
                      
                        for host, nic_id in target.items():

                            if host_down and host in host_down:

                                return "SKIP"
                            else:


                                fault_configuration = dict(nics=[{nic_id : ''}],
                                                                            fault_type=fault_type,
                                                                            fault_args=fault_args,
                                                                            fault_pattern=fault_pattern,
                                                                            fault_pattern_args=fault_pattern_args,
                                                                            fault_target_traffic=fault_target_traffic,
                                                                            fault_target_protocol=fault_target_protocol,
                                                                            fault_target_dst_ports=fault_target_dst_ports,
                                                                            fault_target_src_ports=fault_target_src_ports,
                                                                            pre_injection_time=injector_time_params['pre_injection_time'],
                                                                            injection_time=injector_time_params['injection_time'],
                                                                            post_injection_time=injector_time_params['post_injection_time'],
                                                                            target_name='')
     
                                injector_pool.apply_async(make_post_inject, args = (host, fault_configuration))
                      
    injector_pool.close()
    injector_pool.join()

    return "OK"

@thorfi.route('/inject_switch_port', methods=['POST'])
def inject_switch_port(target_switch_port_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        Method to inject faults at physical target node

    Args:
        target_switch_port_id: is the target switch port ID
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    # get request for injecting in 'router' resource from thorfi client

    target_type = 'switch_port'

    content = request.get_json()

    if content:

        target_switch_port_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)
    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']
        

    logger.info("..............................target_type: %s" % target_type)


    default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']

    global phy_network_topology
    #obtain all the NICs linked to the host attached to the target switch
    #phy_network_topology = thorfiAgent.getPhyNetworkTopology() 

    injector_pool = Pool() 

    target_switch_id = None
    
    thorfi_item_node = {}
    for node in phy_network_topology['nodes']:
      if node['group'] == 7:
        switch_node = node
        for port in node['fault_target']:

                if port['name'] in target_switch_port_id:
                
                    target_switch_id = switch_node['name']


    for node in phy_network_topology['nodes']:

      if node['group'] == 7:
            
          if node['ID'] in target_switch_id:
                
                for port_id, info in node['fault_target_advanced'].items():

                    if port_id in target_switch_port_id:

                        for target in info:
                          
                            for host, nic_id in target.items():
                                
                                if host_down and host in host_down:

                                    return "SKIP"

                                else:

                                    fault_configuration = dict(nics=[{nic_id : ''}],
                                                                                fault_type=fault_type,
                                                                                fault_args=fault_args,
                                                                                fault_pattern=fault_pattern,
                                                                                fault_pattern_args=fault_pattern_args,
                                                                                fault_target_traffic=fault_target_traffic,
                                                                                fault_target_protocol=fault_target_protocol,
                                                                                fault_target_dst_ports=fault_target_dst_ports,
                                                                                fault_target_src_ports=fault_target_src_ports,
                                                                                pre_injection_time=injector_time_params['pre_injection_time'],
                                                                                injection_time=injector_time_params['injection_time'],
                                                                                post_injection_time=injector_time_params['post_injection_time'],
                                                                                target_name='')
         
                                    injector_pool.apply_async(make_post_inject, args = (host, fault_configuration))
                      
    injector_pool.close()
    injector_pool.join()

    return "OK"

@thorfi.route('/inject_node', methods=['POST'])
def inject_node(target_node_id=None, fault_type=None, fault_args=None, fault_pattern=None, fault_pattern_args=None, fault_target_traffic=None, fault_target_protocol=None, fault_target_dst_ports=None, fault_target_src_ports=None, injector_time_params=None):

    """
        Method to inject faults at physical target node

    Args:
        target_node_id: is the target node IP or host name
        fault type: is the fault type to be inject
        fault args: are the fault arguments according to fault type
        injection_time: duration of injection in s

    """
    thorfiAgent = getObjectRef(current_user.agent_ref)
    logger = get_thorfi_app_logger(thorfiAgent)

    # get request for injecting in 'router' resource from thorfi client

    target_type = 'node'

    content = request.get_json()

    if content:

        target_node_id, \
        fault_pattern, \
        fault_pattern_args, \
        fault_target_traffic, \
        fault_target_protocol, \
        fault_target_dst_ports, \
        fault_target_src_ports, \
        fault_type,\
        fault_args, \
        pre_injection_time, \
        injection_time, \
        post_injection_time, \
        injector_time_params = get_thorfi_fault_configuration(logger, content, injector_time_params)
    else:
        pre_injection_time = injector_time_params['pre_injection_time']
        injection_time = injector_time_params['injection_time']
        post_injection_time = injector_time_params['post_injection_time']
        

    logger.info("..............................target_type: %s" % target_type)


    default_injector_port = current_app.config['THORFI_INJECTOR_AGENT_DEFAULT_PORT']

    nics_list = []
    # make_post_inject actually send request to injector agent
    try:

        if host_down and target_node_id in host_down:

            return "SKIP"

        else:


            # Before injection get nics from target_node using 'get_host_nics' API. 
            # note that API return a dict.
            
            target_node_nics = requests.get('http://' + target_node_id + ':' + default_injector_port + '/get_host_nics')
            target_node_nics = json.loads(target_node_nics.text)
            
            # create a list of target nics by the 'target_node_nics' dict 
            for nic, ip in target_node_nics.items():
          
                # NOTE: do not inject in loopback interfaces
                if 'lo' not in nic:
                    nics_list.append({nic:''})
     
     
            fault_configuration = {
                                    'nics': nics_list,
                                    'fault_target_traffic' : fault_target_traffic, 
                                    'fault_target_protocol' : fault_target_protocol,
                                    'fault_target_dst_ports' : fault_target_dst_ports,
                                    'fault_target_src_ports' : fault_target_src_ports,
                                    'fault_type': fault_type,
                                    'fault_pattern': fault_pattern,
                                    'fault_args': fault_args,
                                    'fault_pattern_args' : fault_pattern_args,
                                    'pre_injection_time': injector_time_params['pre_injection_time'],
                                    'injection_time': injector_time_params['injection_time'],
                                    'post_injection_time': injector_time_params['post_injection_time'],
                                    'target_name': ''
                                  }
                  

            make_post_inject(target_node_id, fault_configuration)

        
    except requests.exceptions.ConnectionError as e:

        #TODO: for now we avoid to contact node in which injector agent is not started,
        #      but we need to stop the test actually

        logger.warning("Impossible to reach injector agent on node: %s...skip it" % target_node_id)
        pass 

    return "OK"

