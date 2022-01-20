import flask
import argparse
import time
import sys
import json
import os
import subprocess

from flask import Flask, jsonify, request
from subprocess import call

from injectorAgent import InjectorAgent

from network_utils import get_local_nics

from injector_utils import *

from injector_ping_utils import *
from injector_ssh_utils import *

import logging

if getattr(sys, "frozen", False):
    executable = sys.executable
    injector_agent_path = os.path.dirname(os.path.realpath(executable)) + '/injector_agent_app/'
else:
    executable = __file__
    injector_agent_path = os.path.dirname(os.path.realpath(executable))

injector_agent_log_file = injector_agent_path + '/injector_agent.log'
tc_path = injector_agent_path + '/network_tools/'
cdpr_path = injector_agent_path + '/network_tools/'


#flush 'injector_agent_log_file' log file
open(injector_agent_log_file, 'w').close()

logger = logging.getLogger(__name__)

#set logging both on console and file 'injector_agent_log_file'

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(process)d injector_agent %(levelname)s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(injector_agent_log_file)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)


def GetArgs():
    parser = argparse.ArgumentParser(description='Process args for retrieving arguments')
    parser.add_argument('-i', '--ip', required=True, action='store', help='Host IP on which injector agent is listening')
    parser.add_argument('-p', '--port', required=False, default='11223', action='store', help='Host port on which injector agent is listening')
    args = parser.parse_args()
    return args

class Injector():

    def __init__(self, 
                  target_nics=None, 
                  netns_cmd=None, 
                  fault_target_traffic=None,
                  fault_target_protocol=None,
                  fault_target_dst_ports=None,
                  fault_target_src_ports=None,
                  fault_type=None,
                  fault_pattern=None, 
                  fault_pattern_args=None, 
                  fault_args=None, 
                  target_name=None, 
                  client_auth=None, 
                  nova_client=None, 
                  neutron_client=None, 
                  pre_injection_time=0, 
                  injection_time=20, 
                  post_injection_time=0):

        # target_nics: is a list of network resources to be injected
        # fault: is the fault to be injected in the network resource
        # time: describe how last the injection

        self.target_nics = target_nics
  
        self.fault_target_traffic = fault_target_traffic
        self.fault_target_protocol = fault_target_protocol
        self.fault_target_dst_ports = fault_target_dst_ports
        self.fault_target_src_ports = fault_target_src_ports

        self.netns_cmd = netns_cmd
        self.fault_type = fault_type
        self.fault_pattern = fault_pattern
        self.fault_pattern_args = fault_pattern_args
        self.fault_args = fault_args

        self.pre_injection_time = pre_injection_time
        self.injection_time = injection_time
        self.post_injection_time = post_injection_time

        self.target_name = target_name
        self.client_auth = client_auth
        self.nova_client = nova_client
        self.neutron_client = neutron_client
    
        self.target_protocol_table = {
                                  'ICMP' : '1',
                                  'IGMP' : '2',
                                  'IP' : '4',
                                  'TCP' : '6',
                                  'UDP' : '17',
                                  'IPv6' : '41',
                                  'IPv6-ICMP' : '58'
                                }

    def setTargetNics(self, target_nics):

        self.target_nics = target_nics

    def getTargetNics(self):

        return self.target_nics


    def getFaultTargetTraffic(self):
        return self.fault_target_traffic
 
    def setFaultTargetTraffic(self, fault_target_traffic):
        self.fault_target_traffic = fault_target_traffic
   
    def getFaultTargetProtocol(self):
        return self.fault_target_protocol
 
    def setFaultTargetProtocol(self, fault_target_protocol):
        self.fault_target_protocol = fault_target_protocol
   
    def getFaultTargetDstPorts(self):
        return self.fault_target_dst_ports

    def setFaultTargetDstPorts(self, fault_target_dst_ports):
        self.fault_target_dst_ports = fault_target_dst_ports

    def getFaultTargetSrcPorts(self):
        return self.fault_target_src_ports

    def setFaultTargetSrcPorts(self, fault_target_src_ports):
        self.fault_target_src_ports = fault_target_src_ports

    def getFaultType(self):
        
        return self.fault_type

    def getFaultPattern(self):
        
        return self.fault_pattern

    def setFaultPattern(self, fault_pattern):
        
        self.fault_pattern = fault_pattern

    def getFaultPatternArgs(self):
        
        return self.fault_pattern_args

    def setFaultPatternArgs(self, fault_pattern_args):
        
        self.fault_pattern_args = fault_pattern_args

    def setNetNSCmd(self, netns_cmd):
        self.netns_cmd = netns_cmd
    
    def getNetNSCmd(self):
        return self.netns_cmd

    def setFaultType(self, fault_type):

        self.fault_type = fault_type

    def getFaultArgs(self):

        return self.fault_args

    def setFaultArgs(self, fault_args):

        self.fault_args = fault_args

    def getPreInjectionTime(self):

        return float(self.pre_injection_time)

    def setPreInjectionTime(self, pre_injection_time):
         
        self.pre_injection_time = pre_injection_time

    def getInjectionTime(self):

        return float(self.injection_time)

    def setInjectionTime(self, injection_time):
         
        self.injection_time = injection_time

    def getPostInjectionTime(self):

        return float(self.post_injection_time)

    def setPostInjectionTime(self, post_injection_time):
         
        self.post_injection_time = post_injection_time

    def getTargetName(self):

        return self.target_name

    def setTargetName(self, target_name):
         
        self.target_name = target_name

    def getTargetType(self):

        return self.target_type

    def setTargetType(self, target_type):
         
        self.target_type = target_type

    def getThorFIAuth(self):
        return self.client_auth

    def setThorFIAuth(self, client_auth):
        self.client_auth = client_auth

    def setNovaClient(self, nova_client):
        self.nova_client = nova_client
 
    def setNeutronClient(self, neutron_client):
        self.neutron_client = neutron_client
 
    def getNovaClient(self):
        return self.nova_client
 
    def getNeutronClient(self):
        return self.neutron_client
      

    def create_subnet(self, neutron_client, name, id, netid, cidr, gateway=None):

        logger.info("Create subnet resource name: %s id: %s netid: %s cidr: %s gateway: %s" % (name, id, netid, cidr, gateway))

        resource = 'subnet'
        args = ['--gateway', gateway, netid, cidr, '--description', 'cave']
        position_names = ['ip_version', 'network_id', 'cidr', 'gateway_ip']
        position_values = [4, netid, cidr, gateway]

        body = { resource : {} }
        body[resource].update({'name': name})
        body[resource].update({'ip_version': 4})
        body[resource].update({'network_id': netid})
        body[resource].update({'cidr': cidr})
        body[resource].update({'gateway_ip': gateway})

        subnet = neutron_client.create_subnet(body)
        return subnet['subnet']['id']


    def create_network(self, neutron_client, target_net):

        logger.info("Create OpenStack network resource '%s'" % target_net)
        resource = 'network'
        body = { resource : {} }
        body[resource].update({'name': target_net})

        net = neutron_client.create_network(body)
        net_id = net['network']['id']

        logger.info("Created network resource wiht id %s" % net_id)

        return net_id

    def create_router(self, neutron_client, router_name, tenant_id, network_id):

        resource = 'router'
        body = { resource : {} }
        body[resource].update({'name': router_name})
        body[resource].update({'tenant_id': tenant_id})
        body[resource].update({'admin_state_up': True})
        #body[resource].update({'external_gateway_info': dict(network_id=network_id)})

        router = neutron_client.create_router(body)

        return router['router']['id']


    def get_fip_port_mapping(self, neutron_client, port):
        
        public_ips_list = {}
        fip = None

                
        return fip, public_ips_list


    def do_delete_port(self, neutron_client, port):

        private_ips_list = []
        public_ips_list = {}
        subnet_info = {}
        router_target = None
        gateway_info = None

        #remove before router_interface port
        logger.info("Removing port of type: %s id: %s" % (port['device_owner'], port['id']))
        logger.debug("Port details: %s" % port)

        if port['device_owner'] and (port['device_owner'] in 'network:router_interface' or port['device_owner'] in 'network:router_gateway'):

            # In that case, we perform the following:
            #       1. detach the linked floating ip on the router port
            #       2. remove the port using remove_interface_router
            #
            # Note that we save information to be restored into 'public_ips_list' variable

            router_id = port['device_id']

            router_target = router_id
            logger.debug("Router target to be used during network restoration is %s" % router_target)

            logger.debug("Router ID router_id: %s" % router_id)

            # to remove router_interface port we need to remove all floating ips linked to it
            logger.debug("In order to remove router_interface port we need to remove all floating ips linked to it")
            for floatingips in neutron_client.list_floatingips()['floatingips']:
                
                logger.info("Check for floating ip: %s router_id: %s" % (floatingips['floating_ip_address'], floatingips['router_id']))


                if floatingips['router_id'] and router_id in floatingips['router_id']:

                        logger.debug("Floating IP %s match with router_id %s!" % (floatingips['floating_ip_address'], router_id))
                        logger.info("Disassociate floating ip %s" % floatingips['floating_ip_address'])
                        
                        #save in 'public_ips_list' the link between floating ip and private id
                        public_ips_list[floatingips['floating_ip_address']] = [ floatingips['id'], floatingips['fixed_ip_address'], floatingips['port_id'], None]

                        neutron_client.update_floatingip(floatingips['id'], {'floatingip': {'port_id': None}})


            if port['device_owner'] in 'network:router_interface':

                # now we can remove the router interface
                logger.info("Remove the router interface by identifying the linked subnet through the fixed_ips of the port")
                fixed_ips = port['fixed_ips']
                subnet_index = 0
                for subnet in fixed_ips:

                    subnet_id = subnet['subnet_id']
                    subnet_name = neutron_client.list_subnets(id=subnet_id)['subnets'][subnet_index]['name']
                    subnet_cidr = neutron_client.list_subnets(id=subnet_id)['subnets'][subnet_index]['cidr']
                    subnet_gateway_ip = neutron_client.list_subnets(id=subnet_id)['subnets'][subnet_index]['gateway_ip']
                    subnet_info = { 'subnet_id' : subnet_id, 'subnet_name': subnet_name, 'subnet_cidr': subnet_cidr, 'subnet_gateway_ip': subnet_gateway_ip}

                    logger.debug("Subnet details. id: %s name: %s cidr: %s subnet_gateway_ip: %s" % (subnet_id, subnet_name, subnet_cidr, subnet_gateway_ip))
                    logger.info("Remove from subnet %s the gateway interface linked to router %s" % (subnet['subnet_id'], router_id))
                    
                    neutron_client.remove_interface_router(router_id, {"subnet_id" : subnet['subnet_id'] } )

            elif port['device_owner'] in 'network:router_gateway':

                logger.info("Remove the gateway of router '%s'" % router_id)

                #gateway info is of type: {"network_id": "2b85be5d-4ab4-468a-83ff-0ecf6def2385", "external_fixed_ips": [{"ip_address": "172.24.4.9"}]}
                gateway_info = {'network_id' : port['network_id'], 'external_fixed_ips': [{'ip_address': port['fixed_ips'][0]['ip_address']}]}

                logger.info("Saved info for restoring: %s" % gateway_info)

                # remove the router gateway...save network_id and fixed_ips[0]['ip_address'] for restoring
                neutron_client.remove_gateway_router(router_id)
                time.sleep(1)


        else:
        # remove other types of ports
        #for port in ports_net['ports']: 

            ip = None
            
            #if port['device_owner'] and port['device_owner'] not in 'network:router_interface':

            # we can delete the port simply by calling 'delete_port' api, but before
            # we need to save the private ip of an instance (in that case the 'device_owner' is 'compute:nova', and the instance id (i.e., device_id value)
            # in order to restore it after network deletion
                
            if port['device_owner'] in 'compute:nova':
                
                ip = port['fixed_ips'][0]['ip_address']
                subnet_id = port['fixed_ips'][0]['subnet_id']
                network_id = port['network_id']

                private_ips_list.append( {
                                            ip : 
                                                { 
                                                    'instance_id' : port['device_id'], 
                                                    'subnet_id' : subnet_id,
                                                    'network_id' : network_id
                                                }
                                          } 
                                        )

                #check if that port is linked to a floating ip

                fip = neutron_client.list_floatingips(port_id=port['id'])['floatingips'][0]
                if fip:
                    public_ips_list[fip['floating_ip_address']] = [ fip['id'], fip['fixed_ip_address'], fip['port_id'], None] 

                logger.info("Removing port id %s => %s" % (port['id'], ip))
                neutron_client.delete_port(port['id'])
  
            elif port['device_owner'] in 'network:floatingip':

                # get the fip linked to the target port and then invoke delete_floatingip API

                fip_address = neutron_client.list_ports(id=port['id'])['ports'][0]['fixed_ips'][0]['ip_address']
                if fip_address:

                    fip = neutron_client.list_floatingips(floating_ip_address=fip_address)['floatingips'][0]

                    public_ips_list[fip['floating_ip_address']] = [ None, fip['fixed_ip_address'], fip['port_id'], fip['floating_network_id'] ]

                logger.info("Removing port id %s => %s" % (port['id'], fip_address))
                neutron_client.delete_floatingip(fip['id'])

        return private_ips_list, public_ips_list, subnet_info, router_target, gateway_info


    def do_delete_network_ports(self, neutron_client, ports_net):

        private_ips_list = []
        public_ips_list = {}
        subnet_info = {}
        router_target = None

        #remove before router_interface port
        for port in ports_net['ports']:
       
            time.sleep(1)

            #TODO: we need to handle the case of multiple router_interface!!!

            if port['device_owner'] and port['device_owner'] in 'network:router_interface':

              
                logger.info("Removing port with id: %s" % port['id'])
                logger.debug("Port details: %s" % port)


                logger.debug("Port owner is network:router_interface!")
                # In that case, we perform the following:
                #       1. detach the linked floating ip on the router port
                #       2. remove the port using remove_interface_router

                router_id = port['device_id']

                router_target = router_id
                logger.debug("Router target to be used during network restoration is %s" % router_target)

                logger.debug("Router ID router_id: %s" % router_id)

                # to remove router_interface port we need to remove all floating ips linked to it
                logger.debug("In order to remove router_interface port we need to remove all floating ips linked to it")
                for floatingips in neutron_client.list_floatingips()['floatingips']:
                    
                    logger.info("Check for floating ip: %s router_id: %s" % (floatingips['floating_ip_address'], floatingips['router_id']))


                    if floatingips['router_id'] and router_id in floatingips['router_id']:

                            logger.debug("Floating IP %s match with router_id %s!" % (floatingips['floating_ip_address'], router_id))
                            logger.info("Disassociate floating ip %s" % floatingips['floating_ip_address'])
                            
                            #save in 'public_ips_list' the link between floating ip and private id
                            public_ips_list[floatingips['floating_ip_address']] = [ floatingips['id'], floatingips['fixed_ip_address'], floatingips['port_id']]

                            neutron_client.update_floatingip(floatingips['id'], {'floatingip': {'port_id': None}})


                # now we can remove the router interface
                logger.info("Remove the router interface by identifying the linked subnet through the fixed_ips of the port")
                fixed_ips = port['fixed_ips']
                subnet_index = 0
                for subnet in fixed_ips:

                    subnet_id = subnet['subnet_id']
                    subnet_name = neutron_client.list_subnets(id=subnet_id)['subnets'][subnet_index]['name']
                    subnet_cidr = neutron_client.list_subnets(id=subnet_id)['subnets'][subnet_index]['cidr']
                    subnet_gateway_ip = neutron_client.list_subnets(id=subnet_id)['subnets'][subnet_index]['gateway_ip']
                    subnet_info = { 'subnet_name': subnet_name, 'subnet_cidr': subnet_cidr, 'subnet_gateway_ip': subnet_gateway_ip}

                    logger.debug("Subnet details. id: %s name: %s cidr: %s subnet_gateway_ip: %s" % (subnet_id, subnet_name, subnet_cidr, subnet_gateway_ip))
                    logger.info("Remove from subnet %s the gateway interface linked to router %s" % (subnet['subnet_id'], router_id))
                    neutron_client.remove_interface_router(router_id, {"subnet_id" : subnet['subnet_id'] } )

        # remove other types of ports
        for port in ports_net['ports']: 

            logger.info("Removing port with id: %s" % port['id'])
            logger.debug("Port details: %s" % port)

            if port['device_owner'] and port['device_owner'] not in 'network:router_interface':

                # we can delete the port simply by calling 'delete_port' api, but before
                # we need to save the private ip of an instance (in that case the 'device_owner' is 'compute:nova'
                # in order to restore it after network deletion
                
                ip = None
                fixed_ips = port['fixed_ips']
                for subnet in fixed_ips:
                    ip = subnet['ip_address']

                if port['device_owner'] in 'compute:nova':
                    private_ips_list.append(ip)

                logger.info("Remove port id %s => %s" % (port['id'], ip))
                neutron_client.delete_port(port['id'])

            elif not port['device_owner']:
              
                neutron_client.delete_port(port['id'])

        return private_ips_list, public_ips_list, subnet_info, router_target


    def do_delete_router(self, neutron_client, router_id):

        ret_list = []
        #create ordered list of port so that we remove firstly router interface and then gateway

        for port in neutron_client.list_ports(device_id=router_id)['ports']:
            #delete port
            private_ips_list, public_ips_list, subnet_info, router_target, gateway_info = self.do_delete_port(neutron_client, port)
            ret_list.append(
                              {
                              'old_port_id' : port['id'],
                              'private_ips_list' : private_ips_list, 
                              'public_ips_list' : public_ips_list, 
                              'subnet_info' : subnet_info, 
                              'router_target' : router_target, 
                              'gateway_info' : gateway_info
                              }
                            )

        neutron_client.delete_router(router_id)

        return ret_list


    def restore_fips(self, neutron_client, public_ips_list, restored_port_id):
       
        attach_max_retry = 20
        logger.info("Restoring floating ips linked to previous ports...")
        #restore public ip
        for public_ip, fip_mapping in public_ips_list.items():

            #instance = instances_ips[public_ip]
            #logger.info("Attaching floating IP %s at instance %s" % (public_ip, instance))
            
            fip_id = None
            fip_fixed_ip_address = fip_mapping[1]
            
            public_net_id = fip_mapping[3]
            if public_net_id:
                fip = neutron_client.create_floatingip({ 'floatingip': {'floating_ip_address': public_ip, 'floating_network_id' : public_net_id} })
                fip_id = fip['floatingip']['id']
                #TODO: gestire una lista di floating ip creati!!!!
                restored_fip_id = fip_id

            if not fip_id:
                logger.info("We use old fip_id '%s' because we did not removed it" % (fip_mapping[0]))
                fip_id = fip_mapping[0]

            if not restored_port_id:
                logger.info("We do not recreate a private port before because we did not removed!!!...use old port %s to restore the floating ip '%s'" % (fip_mapping[2], public_ip))
                neutron_client.update_floatingip(fip_id, {'floatingip': {'port_id': fip_mapping[2]}}) 
            else:
                neutron_client.update_floatingip(fip_id, {'floatingip': {'port_id': restored_port_id}}) 

            time.sleep(3)
            
            #check if re-attached floating ip is reachable...in case detach/attach again the private port
            logger.info("Let's try pinging public ip %s" % public_ip)
        
            count_attach = 1

            while count_attach <= attach_max_retry:

                if not check_reachability(public_ip, 10):

                    time.sleep(10)

                    count_attach += 1
                else:
                    
                    logger.info("Ping check on ip %s done!" % public_ip)
                    break

            if count_attach > attach_max_retry:
                logger.error("ThorFI can not ping IP %s. The interface can not be UP for some reasons" % public_ip)
                raise Exception

            #check ssh connection
            ssh_max_retry = 10
            count_ssh = 1
            while count_ssh <= ssh_max_retry:
            
                logger.warning("Try to establish ssh session on ip %s (retry %s)" % (public_ip, count_ssh))
                ssh_session = ssh_connect(public_ip, 'thorfi', injector_agent_path + '/thorfi.key')
                if not ssh_session:
                    count_ssh += 1     
                    time.sleep(1)

                else:

                    logger.info("SSH check on ip %s done!" % public_ip)
                    break

            if count_ssh > ssh_max_retry:
                logger.error("ThorFI can not establish SSH session using IP %s" % public_ip)
                raise Exception


    def do_restore_router(self, neutron_client, router_restore_list, router_name, router_project_id, router_public_net_id):

        restored_port_list = []

        restored_router_id = self.create_router(neutron_client, router_name, router_project_id, router_public_net_id)

        # for each restore element in 'router_restore_list' invoke do_restore_port
  
        logger.info("Restoring port '%s'" % port_to_restore)
        for port_to_restore in router_restore_list:

                restored_port_id, router_interface_id, gateway_port_id = self.do_restore_port(
                                                                                                self.getNovaClient(),
                                                                                                neutron_client,
                                                                                                port_to_restore['private_ips_list'], 
                                                                                                port_to_restore['public_ips_list'], 
                                                                                                port_to_restore['subnet_info'], 
                                                                                                restored_router_id,
                                                                                                port_to_restore['gateway_info'],
                                                                                                False
                                                                                              )
                restored_port_list.append({ port_to_restore['old_port_id'] : [restored_port_id, router_interface_id, gateway_port_id]})
                logger.info("Port '%s' RESTORED! (details: %s)" % port_to_restore)
                time.sleep(5)

        #NOTE: to restore router ports we need to restore all gateway and router interface and THEN public ip list

        #restore fips
        for port_to_restore in router_restore_list:
            self.restore_fips(neutron_client, port_to_restore['public_ips_list'], None)

        return restored_router_id, restored_port_list
        

    def do_delete_network(self, neutron_client, nova_client, net_id):

        """
            do_delete_network performs deletion of OpenStack network resource with id 'network_id'

        """

        ports_net = neutron_client.list_ports(network_id=net_id)
        private_ips_list = []
        public_ips_list = {}
        instances_ips = {}

        for instance in  nova_client.servers.list():

            networks = instance.networks
            for name, ips in networks.items():

              for ip in ips:
                  instances_ips[ip] = instance

        private_ips_list, public_ips_list, subnet_info, router_target = self.do_delete_network_ports(neutron_client, ports_net)

        net_name = neutron_client.list_networks(id=net_id)['networks'][0]['name']
        neutron_client.delete_network(net_id)
        logger.info("Delete network '%s' with id %s" % (net_name, net_id) )

        return private_ips_list, public_ips_list, instances_ips, subnet_info, router_target, net_name

    def check_interface_status(self, neutron_client, port_id, status, attach_max_retry):

        count_attach = 1
        while neutron_client.list_ports(id=port_id)['ports'][0]['status'] not in status and count_attach <= attach_max_retry:
            logger.debug("Wait for port '%s' to be %s" % (port_id, status))
            time.sleep(1)
            count_attach += 1

        if count_attach <= attach_max_retry:
            return True
        else:
            return False

    def check_network_status(self, neutron_client, net_id, status, max_retry):

        count = 1
        while neutron_client.list_networks(id=net_id)['networks'][0]['status'] not in status and count <= max_retry:
            logger.debug("Wait for port '%s' to be %s" % (port_id, status))
            time.sleep(1)
            count += 1

        if count <= max_retry:
            return True
        else:
            return False

    def do_restore_port(self, nova_client, neutron_client, private_ips_list, public_ips_list, subnet_info, router_target, gateway_info, fip_restore=True):
       
        logger.info("Port resource restore start...")

        restored_port_id = None
        router_interface_id = None
        gateway_port_id = None
    
        if subnet_info:
            subnet_id = subnet_info['subnet_id']

        # if port was a router interface we need to add an interface router on 'router_target' for subnet 'subnet_id'
        if router_target and not gateway_info:
            logger.info("Restore router interface with subnet %s" % subnet_id)
            router_interface = neutron_client.add_interface_router(router_target, {'subnet_id' : subnet_id})
            router_interface_id = router_interface['port_id']

        # if port was a router gateway we need to add gateway router on 'router_target' with 'gateway_info'
        elif router_target and gateway_info:
            logger.info("Restore router gateway interface with gateway_info %s" % gateway_info)
            gateway_port = neutron_client.add_gateway_router(router_target, gateway_info)
            
            for router_port in neutron_client.list_ports(device_id=gateway_port['router']['id'])['ports']:
                if 'network:router_gateway' in router_port['device_owner']:
                    gateway_port_id = router_port['id']
                    break
            logger.info("Restored router gateway interface with port id: %s" % gateway_port_id)
    
        time.sleep(5)

        logger.info("Private ip list to restore: %s" % private_ips_list)
        logger.info("Public ip dict to restore: %s" % public_ips_list)

        attach_max_retry = 20

        #restore private
        #for private_ip, instance_id in private_ips_list.items():
        for ipspec in private_ips_list:
            
            for private_ip, port_info in ipspec.items():

                #instance = instances_ips[private_ip]
                instance_id = port_info['instance_id']
                subnet_id = port_info['subnet_id']
                net_id = port_info['network_id']

                logger.info("Attaching interface with IP '%s' at instance: '%s'; subnet: '%s'; network: '%s'" % (private_ip, instance_id, subnet_id, net_id))

                #create a port with neutron
                port_body_value = {
                                "port": {
                                    "admin_state_up": True,
                                    "fixed_ips": [{"subnet_id": subnet_id, "ip_address": private_ip}],
                                    "network_id": net_id
                                }
                              }
               
                #create port for the instance interface
                logger.debug("Creating port with configuration: %s" % port_body_value)
                port_to_add = neutron_client.create_port(body=port_body_value)
                restored_port_id = port_to_add['port']['id']
                time.sleep(5)

                #attach the port with the instance
                nova_client.servers.interface_attach(instance_id, port_id=restored_port_id, net_id=None, fixed_ip=None)

                if not self.check_interface_status(neutron_client, restored_port_id, 'ACTIVE', attach_max_retry):
                    logger.info("Interface %s does not transit in status ACTIVE within %s retries" % (private_ip, attach_max_retry))
                    raise Exception
                else:
                    logger.info("Interface %s transit in status ACTIVE" % private_ip)
        
        logger.info("Wait before attaching floating IP...")
        time.sleep(15)

        if fip_restore:
            
            #restore public ip
            for public_ip, fip_mapping in public_ips_list.items():

                #instance = instances_ips[public_ip]
                #logger.info("Attaching floating IP %s at instance %s" % (public_ip, instance))
                
                fip_id = None
                fip_fixed_ip_address = fip_mapping[1]
                
                public_net_id = fip_mapping[3]
                if public_net_id:
                    fip = neutron_client.create_floatingip({ 'floatingip': {'floating_ip_address': public_ip, 'floating_network_id' : public_net_id} })
                    fip_id = fip['floatingip']['id']
                    #TODO: gestire una lista di floating ip creati!!!!
                    restored_fip_id = fip_id

                if not fip_id:
                    logger.info("We use old fip_id '%s' because we did not removed it" % (fip_mapping[0]))
                    fip_id = fip_mapping[0]

                if not restored_port_id:
                    logger.info("We do not recreate a private port before because we did not removed!!!...use old port %s to restore the floating ip '%s'" % (fip_mapping[2], public_ip))
                    neutron_client.update_floatingip(fip_id, {'floatingip': {'port_id': fip_mapping[2]}}) 
                else:
                    neutron_client.update_floatingip(fip_id, {'floatingip': {'port_id': restored_port_id}}) 

                time.sleep(3)
                
                #check if re-attached floating ip is reachable...in case detach/attach again the private port
                logger.info("Let's try pinging public ip %s" % public_ip)
            
                count_attach = 1

                while count_attach <= attach_max_retry:

                    if not check_reachability(public_ip, 10):

                        time.sleep(10)

                        count_attach += 1
                    else:
                        
                        logger.info("Ping check on ip %s done!" % public_ip)
                        break

                if count_attach > attach_max_retry:
                    logger.error("ThorFI can not ping IP %s. The interface can not be UP for some reasons" % public_ip)
                    raise Exception

                #check ssh connection
                ssh_max_retry = 10
                count_ssh = 1
                while count_ssh <= ssh_max_retry:
                
                    logger.warning("Try to establish ssh session on ip %s (retry %s)" % (public_ip, count_ssh))
                    ssh_session = ssh_connect(public_ip, 'thorfi', injector_agent_path + '/thorfi.key')
                    if not ssh_session:
                        count_ssh += 1     
                        time.sleep(1)

                    else:

                        logger.info("SSH check on ip %s done!" % public_ip)
                        break

                if count_ssh > ssh_max_retry:
                    logger.error("ThorFI can not establish SSH session using IP %s" % public_ip)
                    raise Exception


        logger.info("Port resource restoration completed!")
        logger.info("restored_port_id: '%s' router_interface_id: '%s' gateway_port_id: '%s'" % (restored_port_id, router_interface_id, gateway_port_id))

        return restored_port_id, router_interface_id, gateway_port_id


    def do_restore_network(self, nova_client, neutron_client, target_net, subnet_info, router_target, private_ips_list, public_ips_list, instances_ips):
       
        logger.info("Network resource restore start...")

        subnet_name = subnet_info['subnet_name']
        subnet_cidr = subnet_info['subnet_cidr']
        subnet_gateway_ip = subnet_info['subnet_gateway_ip']

        net_create_max_retry = 10
        net_id = self.create_network(neutron_client, target_net)

        time.sleep(5)

        if not self.check_network_status(neutron_client, net_id, 'ACTIVE', net_create_max_retry):
            logger.error("Network %s does not transit in status ACTIVE within %s retries" % (target_net, net_create_max_retry))
            raise Exception
        else:
            logger.info("Network '%s' transit in status ACTIVE" % target_net)

        subnet_id = self.create_subnet(neutron_client, subnet_name, '', net_id, subnet_cidr, subnet_gateway_ip)
        time.sleep(5)

        if router_target:
            logger.info("Create router interface with subnet %s" % subnet_id)
            neutron_client.add_interface_router(router_target, {'subnet_id' : subnet_id})

        time.sleep(5)

        logger.info("Private ip list to restore: %s" % private_ips_list)
        logger.info("Public ip dict to restore: %s" % public_ips_list)

        attach_max_retry = 20

        #restore private
        for private_ip in private_ips_list:

            instance = instances_ips[private_ip]
            logger.info("Attaching interface with IP %s at instance %s" % (private_ip, instance))

            #create a port with neutron
            port_body_value = {
                            "port": {
                                "admin_state_up": True,
                                "fixed_ips": [{"subnet_id": subnet_id, "ip_address": private_ip}],
                                "network_id": net_id
                            }
                          }
           
            #create port for the instance interface
            logger.debug("Creating port with configuration: %s" % port_body_value)
            port_to_add = neutron_client.create_port(body=port_body_value)

            time.sleep(5)

            #attach the port with the instance
            nova_client.servers.interface_attach(instance.id, port_id=port_to_add['port']['id'], net_id=None, fixed_ip=None)

            if not self.check_interface_status(neutron_client, port_to_add['port']['id'], 'ACTIVE', attach_max_retry):
                logger.info("Interface %s does not transit in status ACTIVE within %s retries" % (private_ip, attach_max_retry))
                raise Exception
            else:
                logger.info("Interface %s transit in status ACTIVE" % private_ip)
        
        logger.info("Wait before attaching floating IP...")
        time.sleep(15)

        #restore public ip
        for public_ip, fip_mapping in public_ips_list.items():

            instance = instances_ips[public_ip]
            logger.info("Attaching floating IP %s at instance %s" % (public_ip, instance))
            fip_id = fip_mapping[0]
            fip_fixed_ip_address = fip_mapping[1]

            neutron_client.update_floatingip(fip_id, {'floatingip': {'port_id': port_to_add['port']['id']}}) 

            time.sleep(3)
            
            #check if re-attached floating ip is reachable...in case detach/attach again the private port
            logger.info("Let's try pinging public ip %s" % public_ip)
        
            count_attach = 1

            while count_attach <= attach_max_retry:

                if not check_reachability(public_ip, 10):

                    logger.warning("During network '%s' restoration the interface with ip %s does not go up!!!!!" % (target_net, private_ip))

                    logger.info("Try (%s) to attach/detach again the port %s" % ( count_attach, port_to_add['port']['id']))

                    nova_client.servers.interface_detach(instance.id, port_to_add['port']['id'])
                   
                    if not self.check_interface_status(neutron_client, port_to_add['port']['id'], 'DOWN', attach_max_retry):
                        logger.info("Interface %s does not transit in status DOWN within %s retries" % (private_ip, attach_max_retry))
                        raise Exception
                    else:
                        logger.info("Interface %s transit in status DOWN" % private_ip)

                    time.sleep(2)

                    logger.info("Attach interface port '%s' at instance '%s'" % (port_to_add['port']['id'], instance.id))
                    nova_client.servers.interface_attach(instance.id, port_id=port_to_add['port']['id'], net_id=None, fixed_ip=None)

                    if not self.check_interface_status(neutron_client, port_to_add['port']['id'], 'ACTIVE', attach_max_retry):
                        logger.info("Interface %s does not transit in status ACTIVE within %s retries" % (private_ip, attach_max_retry))
                        raise Exception
                    else:
                        logger.info("Interface %s transit in status ACTIVE" % private_ip)

                    time.sleep(10)

                    count_attach += 1
                else:
                    
                    logger.info("Ping check on ip %s done!" % public_ip)
                    break

            if count_attach > attach_max_retry:
                logger.error("ThorFI can not ping IP %s. The interface can not be UP for some reasons" % public_ip)
                raise Exception

            #check ssh connection
            ssh_max_retry = 10
            count_ssh = 1
            while count_ssh <= ssh_max_retry:
            
                logger.warning("Try to establish ssh session on ip %s (retry %s)" % (public_ip, count_ssh))
                ssh_session = ssh_connect(public_ip, 'thorfi', injector_agent_path + '/thorfi.key')
                if not ssh_session:
                    count_ssh += 1     
                    time.sleep(1)

                else:

                    logger.info("SSH check on ip %s done!" % public_ip)
                    break

            if count_ssh > ssh_max_retry:
                logger.error("ThorFI can not establish SSH session using IP %s" % public_ip)
                raise Exception


        logger.info("Network resource '%s' restoration completed!" % target_net)

        return net_id

    def do_injection(self):

        #if the fault type is reboot, just use subprocess to reboot the node

        if 'reboot' in self.getFaultType():
            process = subprocess.Popen('reboot -n -f', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # adie' :D
            return
              
        router_name = None
        net_name = None
        neutron_client = self.getNeutronClient()

        logger.debug("Wait %s s of pre-injection time" % self.getPreInjectionTime())
        # wait 'self.pre_injection_time' before injection
        time.sleep(self.getPreInjectionTime())

        if 'burst' in self.getFaultPattern():
           
            burst_config = self.getFaultPatternArgs()
            burst_duration = float(burst_config[0])/1000
            burst_period = float(burst_config[1])/1000
            
            logger.info("injection time : %s" % self.getInjectionTime())
            burst_num = int((self.getInjectionTime()) / burst_period)
            
            logger.info("Burst config: burst_duration: %s burst_period: %s burst_num: %s" % (burst_duration, burst_period, burst_num))

            for i in range(burst_num):

                #iterate over all target devices to enable injection
                for nic_netns in self.getTargetNics():
                  
                    for nic, netns in nic_netns.items():
                    
                        if nic:
                            logger.debug("BURST ENABLE injection on nic %s netns %s" % (nic, netns))

                            self.inject_nics(nic, netns, self.getFaultType(), 'persistent', [''], self.getFaultArgs(), self.getFaultTargetTraffic(), self.getFaultTargetProtocol(), self.getFaultTargetDstPorts(), self.getFaultTargetSrcPorts(), True)

                logger.debug("WAIT BURST DURATION...%s" % burst_duration)
                time.sleep(burst_duration)

                for nic_netns in self.getTargetNics():
                  
                    for nic, netns in nic_netns.items():
                    
                        if nic:

                            logger.debug("BURST DISABLE injection on nic %s netns %s" % (nic, netns))
                            self.inject_nics(nic, netns, self.getFaultType(), 'persistent', [''], self.getFaultArgs(), self.getFaultTargetTraffic(), self.getFaultTargetProtocol(), self.getFaultTargetDstPorts(), self.getFaultTargetSrcPorts(), False)

                logger.debug("WAIT BURST remaining time...%s" % (burst_period - burst_duration))
                time.sleep(burst_period - burst_duration)

        elif 'degradation' in self.getFaultPattern():
            
            
            # increment for 'fault_pattern_args' each second
            degradation_step = 1
            degradation_config = self.getFaultPatternArgs()
            degradation_value = degradation_config[0]

            logger.info("Degradation fault pattern!!!! Start with %s perc/s" % degradation_value)

            for i in range(int(self.getInjectionTime())):
                
                logger.info("#%s step..." % i)
                #iterate over all target devices to enable injection
                for nic_netns in self.getTargetNics():
                  
                    for nic, netns in nic_netns.items():
                    
                        if nic:
                            logger.debug("DEGRADATION ENABLE injection on nic %s netns %s" % (nic, netns))

                            self.inject_nics(nic, netns, self.getFaultType(), 'random', [degradation_value], self.getFaultArgs(), self.getFaultTargetTraffic(), self.getFaultTargetProtocol(), self.getFaultTargetDstPorts(), self.getFaultTargetSrcPorts(), True)

                logger.debug("WAIT DEGRADATION DURATION...%s" % degradation_step)
                time.sleep(degradation_step)

                for nic_netns in self.getTargetNics():
                  
                    for nic, netns in nic_netns.items():
                    
                        if nic:

                            logger.debug("DEGRADATION DISABLE injection on nic %s netns %s" % (nic, netns))
                            self.inject_nics(nic, netns, self.getFaultType(), 'random',  [degradation_value], self.getFaultArgs(), self.getFaultTargetTraffic(), self.getFaultTargetProtocol(), self.getFaultTargetDstPorts(), self.getFaultTargetSrcPorts(), False)

              
                degradation_value = str( int(degradation_value) + int(degradation_config[0]) )
                if int(degradation_value) > 100:
                    degradation_value = str(100)

                logger.debug("updated degradation value %s" % degradation_value)

        else:

            if 'delete' in self.getFaultType():
            
                if 'network' in self.getTargetType():

                    net_id = None
                    restored_resources = None

                    for net in neutron_client.list_networks()['networks']:

                        if net['id'] in self.getTargetName():
                            net_id = net['id']
                            break

                    logger.debug("Enable injection deletion on network '%s'" % self.getTargetName())
                    private_ips_list, public_ips_list, instances_ips, subnet_info, router_target, net_name = self.do_delete_network(neutron_client, self.getNovaClient(), net_id)
                
                elif 'port' in self.getTargetType():
                    
                    port_id = self.getTargetName()
                    target_port = neutron_client.list_ports(id=port_id)['ports'][0]
                    print target_port
                    private_ips_list, public_ips_list, subnet_info, router_target, gateway_info = self.do_delete_port(neutron_client, target_port)
                    print private_ips_list, public_ips_list, subnet_info, router_target, gateway_info

                elif 'router' in self.getTargetType():
                    
                    router_id = self.getTargetName()

                    router_name = neutron_client.list_routers(id=router_id)['routers'][0]['name']
                    router_project_id = neutron_client.list_routers(id=router_id)['routers'][0]['project_id']
                    router_public_net_id = neutron_client.list_routers(id=router_id)['routers'][0]['external_gateway_info']['network_id']

                    router_restore_list = self.do_delete_router(neutron_client, router_id)

                    logger.debug("router_restore_list: %s" % router_restore_list)

            else:  

                #iterate over all target devices to enable injection
                for nic_netns in self.getTargetNics():
                  
                    for nic, netns in nic_netns.items():
                    
                        if nic:
                            logger.debug("Enable injection on nic %s netns %s" % (nic, netns))

                            self.inject_nics(nic, netns, self.getFaultType(), self.getFaultPattern(), self.getFaultPatternArgs(), self.getFaultArgs(), self.getFaultTargetTraffic(), self.getFaultTargetProtocol(), self.getFaultTargetDstPorts(), self.getFaultTargetSrcPorts(), True)
           
            logger.info("Wait the injection time (%s s)" % self.getInjectionTime())
            time.sleep(self.getInjectionTime())
            
            if 'delete' in self.getFaultType():

                logger.debug("Disable injection deletion on '%s' '%s'" % (self.getTargetType(), self.getTargetName()))
                
                if 'network' in self.getTargetType():
                    
                    restored_resources = self.do_restore_network(self.getNovaClient(), self.getNeutronClient(), net_name, subnet_info, router_target, private_ips_list, public_ips_list, instances_ips)

                elif 'port' in self.getTargetType():

                    restored_port_id, router_interface_id, gateway_port_id = self.do_restore_port(self.getNovaClient(), self.getNeutronClient(), private_ips_list, public_ips_list, subnet_info, router_target, gateway_info)

                elif 'router' in self.getTargetType():

                    restored_router_id, restored_port_list = self.do_restore_router(self.getNeutronClient(), router_restore_list, router_name, router_project_id, router_public_net_id)

                    logger.debug("restored_port_list >>>>>>>>>>>>>> %s" % restored_port_list)

            else:
                
                #iterate over all target devices to disable injection
                for nic_netns in self.getTargetNics():

                    for nic, netns in nic_netns.items():
                  
                        if nic:
                            logger.debug("Disable injection on nic %s netns %s" % (nic, netns))
         
                            self.inject_nics(nic, netns, self.getFaultType(), self.getFaultPattern(), self.getFaultPatternArgs(), self.getFaultArgs(), self.getFaultTargetTraffic(), self.getFaultTargetProtocol(), self.getFaultTargetDstPorts(), self.getFaultTargetSrcPorts(), False)

        ################ END INJECTION CODE ###################

        # wait 'self.post_injection_time' after removing injection injection
        logger.debug("Wait %s s of post-injection time" % self.getPostInjectionTime())
        time.sleep(self.getPostInjectionTime())

        if 'delete' in self.getFaultType():
            
            if 'network' in self.getTargetType():

                return [{net_id : restored_resources}]

            elif 'port' in self.getTargetType():

                res = (restored_port_id, router_interface_id, gateway_port_id)
                restored = [port for port in res if port] 
                return [{self.getTargetName() : restored[0]}]

            elif 'router' in self.getTargetType():
            
                restored_old_new_port = []
                # get pair old_port_id : new_port_id
                for port_info in restored_port_list:

                    for old_port_id, restored_info in port_info.items():

                        restored = [port for port in tuple(restored_info) if port]
                        
                        restored_old_new_port.append({ old_port_id : restored[0] })

                restored_old_new_port.append({self.getTargetName() : restored_router_id})

                return restored_old_new_port
                #logger.debug("restored_old_new_port LIST : %s" % restored_old_new_port) 
                

        else:
            
            return

    def make_nics_injection_command(self, netns_cmd, netns, device, fault_type, fault_pattern, fault_pattern_args, fault_args, tc_cmd):

        logger.debug("[make_nics_injection_command] CONFIG: netns_cmd %s, netns %s, device %s, fault_type %s, fault_pattern %s, fault_pattern_args %s, fault_args %s, tc_cmd %s"
                      % (netns_cmd, netns, device, fault_type, fault_pattern, fault_pattern_args, fault_args, tc_cmd))

        command = None

        # NOTE: for NODE_DOWN and NIC_DOWN fault type does not make sense the random fault_pattern.
        #       we implement only a persistent flavor

        if 'random' in fault_pattern:

            if 'delay' in fault_type:
              # e.g., tc qdisc add dev tap0897f3c6-e0 root netem delay 50ms reorder 50%
              random_perc = 100 - int(fault_pattern_args)
              command = netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc ' + tc_cmd + ' dev ' + device + ' root netem ' + fault_type + ' ' + fault_args + ' reorder ' + str(random_perc) + '%'

            else:
              # in that case for corruption and loss we can use the 'fault_args' that already include random probability
              command = netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc ' + tc_cmd + ' dev ' + device + ' root netem ' + fault_type + ' ' + fault_pattern_args + '%'

        elif 'persistent' in fault_pattern:
            
            # Persistent fault type means setting a probability to 100%. For delay injection we can just use the default usage for 'delay' fault type
            
            if 'delay' in fault_type:
             

              command = netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc ' + tc_cmd + ' dev ' + device + ' root netem ' + fault_type + ' ' + fault_args

            elif 'bottleneck' in fault_type:
    
              #the command is like: tc qdisc add dev tapa68bfef8-df root tbf rate 256kbit burst 1600 limit 3000
              default_bottleneck_burst='1600'
              default_limit_burst='3000'
              command = netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc ' + tc_cmd + ' dev ' + device + ' root tbf rate ' + fault_args + 'kbit burst ' + default_bottleneck_burst + ' limit ' + default_limit_burst 

            elif 'down' in fault_type:

                if 'add' in tc_cmd:
                  
                    #search for ifdown cmd
                    p = subprocess.Popen('whereis -b ifdown | awk \'{print $2}\'', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    output, err = p.communicate()
                    ifdown_cmd = output.strip()
                    if ifdown_cmd:
                        command = netns_cmd + ' ' + netns + ' ' + ifdown_cmd + ' ' + device

                elif 'del' in tc_cmd:
                    #search for ifdown cmd
                    p = subprocess.Popen('whereis -b ifup | awk \'{print $2}\'', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    output, err = p.communicate()
                    ifup_cmd = output.strip()
                    if ifup_cmd:
                        command = netns_cmd + ' ' + netns + ' ' + ifup_cmd + ' ' + device


            else:
              # in that case for corruption and loss we can use the 'fault_args' to set 100% probability

              command = netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc ' + tc_cmd + ' dev ' + device + ' root netem ' + fault_type + ' 100%'

        return command

    def make_filter_cmds(self, fault_pattern, fault_pattern_args, fault_type, fault_args, netns_cmd, netns, device, target_protocol, target_dst_ports=None, target_src_ports=None, enable=False):

        logger.debug("[make_filter_cmds] CONFIG: fault_pattern %s, fault_pattern_args %s, fault_type %s, fault_args %s, netns_cmd %s, netns %s, device %s, target_protocol %s, target_dst_ports %s, target_src_ports %s, enable %s"
                      % (fault_pattern, fault_pattern_args, fault_type, fault_args, netns_cmd, netns, device, target_protocol, target_dst_ports, target_src_ports, enable))
        if enable:

            cmd_list = [ netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' root handle 1: prio' ]

            target_protocol_cmd = 'match ip protocol ' + self.target_protocol_table[target_protocol] + ' 0xff'

            if target_dst_ports:
                for target_port in target_dst_ports:
                    target_port_cmd = 'match ip dport ' + str(target_port) + ' 0xffff'
                    cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc filter add dev ' + device + ' parent 1:0 protocol ip prio 1 u32 ' + target_protocol_cmd + ' ' + target_port_cmd + ' flowid 1:1')

            if target_src_ports:
                for target_port in target_src_ports:
                    target_port_cmd = 'match ip sport ' + str(target_port) + ' 0xffff'
                    cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc filter add dev ' + device + ' parent 1:0 protocol ip prio 1 u32 ' + target_protocol_cmd + ' ' + target_port_cmd + ' flowid 1:1')

            else:
                cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc filter add dev ' + device + ' parent 1:0 protocol ip prio 1 u32 ' + target_protocol_cmd + ' flowid 1:1')

            # enable fault injection

            if 'random' in fault_pattern:
                
                if 'delay' in fault_type:
                    # e.g., tc qdisc add dev tap0897f3c6-e0 root netem delay 50ms reorder 50%
                    random_perc = 100 - int(fault_pattern_args)
                    cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: netem ' + fault_type + ' ' + fault_args + ' reorder ' + str(random_perc) + '%')
                else:
                    cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: netem ' + fault_type + ' ' + fault_pattern_args + '%')

            elif 'persistent' in fault_pattern:

                
                if 'bottleneck' in fault_type:
        
                  #the command is like: tc qdisc add dev tapa68bfef8-df root tbf rate 256kbit burst 1600 limit 3000
                  default_bottleneck_burst='1600'
                  default_limit_burst='3000'
                  cmd_list.appen(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: tbf rate ' + fault_args + 'kbit burst ' + default_bottleneck_burst + ' limit ' + default_limit_burst)

                else:
                    if 'delay' in fault_type:
                        tc_arg = fault_args
                    else:
                        tc_arg = '100%'

                    cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: netem ' + fault_type + ' ' + tc_arg)
           
        else:
            cmd_list = []
            cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc del dev ' + device + ' root handle 1: prio')

        logger.debug("cmd_list generated => %s" % cmd_list)

        return cmd_list



    def inject_nics(self, device, netns, fault_type, fault_pattern, fault_pattern_args, fault_args, target_traffic, target_protocol, target_dst_ports, target_src_ports, enable):

        # tc/netem commands used to inject fault
        #
        # fault_type = [ delay | loss | corrupt | duplicate | bottleneck | down | reboot]
        # fault_args = [<latency>ms | <percentage>%]
        #
        # DELAY:
        # tc qdisc add dev <nic> root netem delay <latency>ms"
        #
        # LOSS:
        # tc qdisc add dev <nic> root netem loss <percentage>%
        #
        # CORRUPT:
        # tc qdisc change dev <nic> root netem corrupt <percentage>%
    

        #NOTE: to handle properly floating ip injection we need to filter on floating ip
        #
        # Example:
        #
        # to enable:
        # ip netns exec qrouter-8f998d26-79e1-41ff-8fd8-ba362ab4fc92 tc qdisc add dev qg-a931d750-88 root handle 1: prio
        # ip netns exec qrouter-8f998d26-79e1-41ff-8fd8-ba362ab4fc92 tc filter add dev qg-a931d750-88 parent 1:0 protocol ip prio 1 u32 match ip src 10.0.20.232 flowid 1:1
        # ip netns exec qrouter-8f998d26-79e1-41ff-8fd8-ba362ab4fc92 tc filter add dev qg-a931d750-88 parent 1:0 protocol ip prio 1 u32 match ip dst 10.0.20.232 flowid 1:1
        # ip netns exec qrouter-8f998d26-79e1-41ff-8fd8-ba362ab4fc92 tc qdisc add dev qg-a931d750-88 parent 1:1 handle 2: netem delay 1000ms
        #
        # to disable:
        # ip netns exec qrouter-8f998d26-79e1-41ff-8fd8-ba362ab4fc92 tc qdisc add dev qg-a931d750-88 root handle 1: prio

        netns_cmd = ''
        
        if netns:
            netns_cmd = 'ip netns exec'

        # NOTE: if self.getTargetName is not None it means that we are injecting in a floating IP address for virtual networks
        if self.getTargetName():

            cmd_list = []
            logger.debug("Target name is not None, it is an floating IP address: %s" % self.getTargetName())
            logger.debug("Use FILTER MODE of tc during injection.")
           
            #skip injection on qr device when floatingip because we must target only the qg-XXX device
        
            if 'qg' in device:

                  if enable:

                      cmd_list = [  netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' root handle 1: prio',  
                                    netns_cmd + ' ' + netns + ' ' + tc_path + '/tc filter add dev ' + device + ' parent 1:0 protocol ip prio 1 u32 match ip src ' + self.getTargetName() + ' flowid 1:1',
                                    netns_cmd + ' ' + netns + ' ' + tc_path + '/tc filter add dev ' + device + ' parent 1:0 protocol ip prio 1 u32 match ip dst ' + self.getTargetName() + ' flowid 1:1',
                                  ]

                      # enable fault injection

                      if 'random' in fault_pattern:
                          
                          if 'delay' in fault_type:
                              # e.g., tc qdisc add dev tap0897f3c6-e0 root netem delay 50ms reorder 50%
                              random_perc = 100 - int(fault_pattern_args[0])
                              cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: netem ' + fault_type + ' ' + fault_args + ' reorder ' + str(random_perc) + '%')
                          else:
                              cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: netem ' + fault_type + ' ' + fault_pattern_args[0] + '%')

                      elif 'persistent' in fault_pattern:
  
                          if 'delay' in fault_type:
                              tc_arg = fault_args
                          else:
                              tc_arg = '100%'

                          cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc add dev ' + device + ' parent 1:1 handle 2: netem ' + fault_type + ' ' + tc_arg)
                     
                  else:
                      cmd_list = []
                      cmd_list.append(netns_cmd + ' ' + netns + ' ' + tc_path + '/tc qdisc del dev ' + device + ' root handle 1: prio')

                  for command in cmd_list:

                      logger.debug("Execute command: '%s'" % command)
                      retcode = call(command, shell=True)
                      
                      if retcode < 0:
                          logger.debug("Command '%s' was terminated not correctly (recode %s)" % (command, -retcode))
                      else:
                          logger.debug("Command '%s' was terminated correctly (retcode %s)" % (command, retcode))
            
            else:
                logger.info("During injection of floatingip qr-XXX device will not be injected!")

        # NOTE: if self.getTargetName is None we are injecting on the other network resources except floating IP
        else:

            # if fault target is ANY_TRAFFIC call make_nics_injection_command

            if 'any' in target_traffic:

                if enable:
                    # enable fault injection
                    
                    command = self.make_nics_injection_command(netns_cmd, netns, device, fault_type, fault_pattern, fault_pattern_args[0], fault_args, 'add')
                else:
                    command = self.make_nics_injection_command(netns_cmd, netns, device, fault_type, fault_pattern, fault_pattern_args[0], fault_args, 'del')

                logger.debug("Execute command: '%s'" % command)

                retcode = call(command, shell=True)

                if retcode < 0:
                    logger.debug("Command '%s' was terminated not correctly (recode %s)" % (command, -retcode))
                else:
                    logger.debug("Command '%s' was terminated correctly (retcode %s)" % (command, retcode))
            
            
            # if fault target is not ANY_TRAFFIC generate cmds for injecting according to protocol and port number
            else:

                cmd_list = []
              
                if enable:
                    cmd_list = self.make_filter_cmds(fault_pattern, fault_pattern_args[0], fault_type, fault_args, netns_cmd, netns, device, target_protocol, target_dst_ports, target_src_ports, True)
                else:
                    cmd_list = self.make_filter_cmds(fault_pattern, fault_pattern_args[0], fault_type, fault_args, netns_cmd, netns, device, target_protocol, target_dst_ports, target_src_ports, False)
              
                for command in cmd_list:

                    logger.debug("Execute command: '%s'" % command)
                    retcode = call(command, shell=True)
                    
                    if retcode < 0:
                        logger.debug("Command '%s' was terminated not correctly (recode %s)" % (command, -retcode))
                    else:
                        logger.debug("Command '%s' was terminated correctly (retcode %s)" % (command, retcode))

        


args = GetArgs()
host_ip = args.ip
host_port = args.port
is_debug = False
is_threaded = True

# create new instance of InjectorAgent within args 
injectorAgent = InjectorAgent(host_ip, host_port, is_threaded, is_debug)

# get instance of newly created injector agent
agent = injectorAgent.getInjectorAgent()


# list of provided APIs
#
# set_target_nics
# get_target_nics
# set_fault
# get_fault
# set_fault_args
# get_fault_args
# inject

# alive method
@agent.route('/alive', methods=['GET'])
def alive():
    logger.info("I'm alive!")
    return "OK"

@agent.route('/set_target_nics', methods=['POST'])
def set_target_nics():

    # set_target_nics save the list of nics to be injected
    device = None
    #get device from the post

    injector.setTarget(device)

    return "OK"

@agent.route('/get_target_nics', methods=['GET'])
def get_target_nics():
    
    # get_target_nics return the list of nics to be injected

    return jsonify(injector.getTarget())


@agent.route('/inject', methods=['POST'])
def inject():
    
    #create an Injector object used to actual inject faults
    injector = Injector()

    content = request.get_json()

    restored_resources = {}
  
    logger.debug("Received data %s" % request.get_json())

    target_nics = content['nics']

    fault_target_traffic = content.get('fault_target_traffic', None)
    fault_target_protocol = content.get('fault_target_protocol', None)
    fault_target_dst_ports = content.get('fault_target_dst_ports', None)
    fault_target_src_ports = content.get('fault_target_src_ports', None)

    fault_type = content['fault_type']
    fault_args = content['fault_args']
    fault_pattern = content.get('fault_pattern', None)
    fault_pattern_args = content.get('fault_pattern_args', None)
    
    pre_injection_time = content['pre_injection_time']
    injection_time = content['injection_time']
    post_injection_time = content['post_injection_time']
    target_name = content['target_name']
    target_type = content.get('target_type', None)

    injector.setTargetNics(target_nics)

    injector.setFaultTargetTraffic(fault_target_traffic)
    injector.setFaultTargetProtocol(fault_target_protocol)
    injector.setFaultTargetDstPorts(fault_target_dst_ports)
    injector.setFaultTargetSrcPorts(fault_target_src_ports)

    injector.setFaultType(fault_type)
    injector.setFaultPattern(fault_pattern)
    injector.setFaultPatternArgs(fault_pattern_args)
    injector.setFaultArgs(fault_args)
    injector.setPreInjectionTime(pre_injection_time)
    injector.setInjectionTime(injection_time)
    injector.setPostInjectionTime(post_injection_time)
    injector.setTargetName(target_name)
    injector.setTargetType(target_type)

    # if the injector agent receive 'client_auth' data from POST we need to setup nova and neutron client objs
    try:
        if content['client_auth']:
            client_auth = content['client_auth']
            injector.setThorFIAuth(client_auth)
            nova_cli = get_client('nova',
                                                    client_auth['auth_url'],
                                                    client_auth['username'],
                                                    client_auth['password'],
                                                    client_auth['project_name'],
                                                    client_auth['project_domain_id'],
                                                    client_auth['user_domain_id']
                                                )
            injector.setNovaClient(nova_cli)
            neutron_cli = get_client('neutron',
                                                    client_auth['auth_url'],
                                                    client_auth['username'],
                                                    client_auth['password'],
                                                    client_auth['project_name'],
                                                    client_auth['project_domain_id'],
                                                    client_auth['user_domain_id']
                                                )
            injector.setNeutronClient(neutron_cli)
    except KeyError:
        logger.warning("'client_auth' field is not in the request...go on!")

    restored_resources = injector.do_injection()    


    logger.info("restored_res %s" % restored_resources)
    logger.info("Injection ENDS")

    if restored_resources:
        return json.dumps(restored_resources)
    else:
        return "OK"

@agent.route('/get_host_nics', methods=['GET'])
def get_host_nics():

    local_nics = get_local_nics()
    logger.debug("Local NICS: %s" % local_nics)
    return json.dumps(local_nics)

@agent.route('/get_l2_info', methods=['POST'])
def get_l2_info():

    # execute command 'cdpr -d NIC'
  
    content = request.get_json()

    logger.debug("Received data %s" % request.get_json())

    target_nic = content['nic']

    LD_LIBRARY_PATH = injector_agent_path + "/network_tools/"
    CDPR_COMMAND = cdpr_path + '/cdpr -t 60 -d ' + target_nic

    #process = subprocess.Popen(cdpr_path + '/cdpr -t 60 -d ' + target_nic, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logger.debug("CDPR command: %s" % ("LD_LIBRARY_PATH=" + LD_LIBRARY_PATH + ":$LD_LIBRARY_PATH "+ CDPR_COMMAND))

    process = subprocess.Popen("LD_LIBRARY_PATH=" + LD_LIBRARY_PATH + ":$LD_LIBRARY_PATH "+ CDPR_COMMAND, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    out = process.communicate()[0]
    rc = process.returncode

    if not rc:

        # Right output example:
        # ['cdpr - Cisco Discovery Protocol Reporter', 'Version 2.4', 'Copyright (c) 2002-2010 - MonkeyMental.com', '', 'Using Device: eth0', 'Waiting for CDP advertisement:', '(default config is to transmit CDP packets every 60 seconds)', 'Device ID', '  value:  CN0H784T2829846B0010A01', 'Addresses', '  value:  172.28.21.251', 'Port ID', '  value:  Gi1/0/28', '']
        #
      
        l2_info_str =  out.split('\n')

        logger.debug("l2_info_str: %s" % l2_info_str)

        #device_id = l2_info_str[9].split(':')[1].strip()
        
        port_id = 'unknown'
        device_id = 'unknown'
        addresses = 'unknown'

        for index in range(0, len(l2_info_str)-1):
            
            if l2_info_str[index] in 'Port ID' and 'value' in l2_info_str[index+1]:
                port_id = l2_info_str[index+1].split(':')[1].strip()

            elif l2_info_str[index] in 'Device ID' and 'value' in l2_info_str[index+1]:
                device_id = l2_info_str[index+1].split(':')[1].strip()


        l2_info = {'device_id':device_id, 'addresses': addresses, 'port_id': port_id}
      
        logger.info("L2 info: %s" % l2_info)

        return json.dumps(l2_info)

    else:
        logger.warning("Unable to retrieve L2 info!")

    return "ERROR"



"""
        ################### IPERF WORKLOAD API ###################
"""

@agent.route('/start_thorfi_workload_iperf', methods=['POST'])
def start_thorfi_workload_iperf():

    logger.info("start_thorfi_workload_iperf STARTED!")
    
    LD_LIBRARY_PATH = injector_agent_path + "/workload_generators/iperf/linux/"   
    IPERF3_PATH = injector_agent_path + "/workload_generators/iperf/linux/"
    IPERF_LOG_PATH = injector_agent_path + "/workload_generators/iperf/"
    IPERF_CMD = "iperf3"
    
    content = request.get_json()
    
    if 'client' in content['role']:
        
        if 'udp' in content['iperf_protocol']:
            IPERF_CMD += ' -c ' + content['server_host_ip'] + ' -p ' + content['iperf_server_port'] + ' -t 0 -b ' + content['iperf_bandwidth'] + ' -f k -u -J --logfile ' + IPERF_LOG_PATH + 'iperf_client.log &'

        elif 'tcp' in content['iperf_protocol']:
            IPERF_CMD += ' -c ' + content['server_host_ip'] + ' -p ' + content['iperf_server_port'] + ' -t 0 -b ' + content['iperf_bandwidth'] + ' -f k -J --logfile ' + IPERF_LOG_PATH + 'iperf_client.log &'

    elif 'server' in content['role']:

        IPERF_CMD += ' -s -p ' + content['iperf_server_port'] + ' -f k -J --logfile ' + IPERF_LOG_PATH + 'iperf_server.log &'

    logger.debug("start_thorfi_workload_iperf CMD ==> %s" %IPERF_CMD)

    process = subprocess.Popen("LD_LIBRARY_PATH=" + LD_LIBRARY_PATH + ":$LD_LIBRARY_PATH "+ IPERF3_PATH + IPERF_CMD, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    logger.debug("##################### PROC_CMD : LD_LIBRARY_PATH=%s:$LD_LIBRARY_PATH %s%s" %(LD_LIBRARY_PATH, IPERF3_PATH, IPERF_CMD))

    logger.info("start_thorfi_workload_iperf ENDED!")

    return "OK"


@agent.route('/stop_thorfi_workload_iperf', methods=['GET'])
def stop_thorfi_workload_iperf():

    logger.info("stop_thorfi_workload_iperf STARTED!")

    process = subprocess.Popen("ps aux|grep iperf |grep -v grep|awk '{print $2}' | xargs kill -SIGTERM", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = process.communicate()

    logger.info("stop_thorfi_workload_iperf ENDED!")

    if not err: 
        return "OK"
    else:
        return "ERROR"


@agent.route('/save_logs_iperf', methods=['POST'])
def save_logs_iperf():

    content = request.get_json()
    
    iperf_role = content.get('role')
    
    logger.info("save_workload_logs_iperf_%s STARTED!" %iperf_role)

    iperf_path = injector_agent_path + '/workload_generators/iperf'

    try:
        with open(iperf_path + '/iperf_' + iperf_role + '.log','r') as f:
            logger.info("File iperf_%s.log found" %iperf_role)
            return json.dumps(f.read())
   
    except IOError as e:
        logger.info("File iperf_%s.log Not Found" %iperf_role)
        return "ERROR"


@agent.route('/prepare_thorfi_workload_iperf', methods=['POST'])
def prepare_thorfi_workload_iperf():

    content = request.get_json()
    
    logger.info("prepare_thorfi_workload_iperf STARTED!")

    iperf_path = injector_agent_path + '/workload_generators/iperf'

    iperf_role = content.get('role')

    #flush old iperf_client.log or iperf_server.log
    try:
        with open(iperf_path + '/iperf_' + iperf_role + '.log','w') as f:
            logger.info("Removed old iperf_%s.log OK" %iperf_role)
            pass
    except IOError as e:
        logger.info("Removed old summary.csv file ERROR : %s" %e)
        return "ERROR"

    return "OK"           




"""
        ################### JMETER WORKLOAD API ###################
"""

@agent.route('/start_thorfi_workload_jmeter', methods = ['GET'])
def start_thorfi_workload_jmeter():

    logger.info("start_thorfi_workload_jmeter STARTED!")

    JAVA_HOME = injector_agent_path + "/workload_generators/jmeter/jdk-11.0.2/"
    PATH = injector_agent_path + "/workload_generators/jmeter/jdk-11.0.2/bin/"
    WL_PATH = injector_agent_path + "/workload_generators/jmeter/apache-jmeter-5.0/bin/"

    JMETER_PATH = injector_agent_path + "/workload_generators/jmeter/"
    JMX_FILE = JMETER_PATH + "jmeter_workload.jmx"
    JMETER_SUMMARY_LOG = JMETER_PATH + "summary.csv"
    JMETER_LOG = JMETER_PATH + "jmeter.log"
    
    JMETER_CMD = "/jmeter.sh -n -t " + JMX_FILE + " -l " + JMETER_SUMMARY_LOG + ' -j ' + JMETER_LOG + '  &'

    logger.debug("start_thorfi_workload_jmeter CMD ==> %s" %JMETER_CMD)

    process = subprocess.Popen("JAVA_HOME=" + JAVA_HOME +"  PATH=" + PATH +":$PATH " + WL_PATH + JMETER_CMD, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    logger.info("start_thorfi_workload_jmeter ENDED!")

    return "OK"


@agent.route('/check_thorfi_workload_jmeter', methods = ['GET'])
def check_thorfi_workload_jmeter():

    logger.info("check_thorfi_workload_jmeter STARTED!")

    jmeter_path = injector_agent_path + '/workload_generators/jmeter/'
    
    process = subprocess.Popen('cat ' + jmeter_path + 'jmeter.log | grep "Sample TimeStamps are START times" > /dev/null 2>&1; echo $?', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = process.communicate()
    
    if not err:
        return json.dumps(out)
    else:
        return "ERROR"


@agent.route('/stop_thorfi_workload_jmeter', methods=['GET'])
def stop_thorfi_workload_jmeter():

    logger.info("stop_thorfi_workload_jmeter STARTED!")

    JAVA_HOME = injector_agent_path + "/workload_generators/jmeter/jdk-11.0.2/"
    PATH = injector_agent_path + "/workload_generators/jmeter/jdk-11.0.2/bin/"
    WL_PATH = injector_agent_path + "/workload_generators/jmeter/apache-jmeter-5.0/bin/"
    JMETER_CMD = "/stoptest.sh"
    process = subprocess.Popen("JAVA_HOME=" + JAVA_HOME +"  PATH=" + PATH +":$PATH " + WL_PATH + JMETER_CMD, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = process.communicate()

    logger.info("stop_thorfi_workload_jmeter ENDED!")
    
    if not err:
        return "OK"
    else:
        return "ERROR"


@agent.route('/save_logs_jmeter', methods=['GET'])
def save_logs_jmeter():

    logger.info("save_logs_jmeter STARTED!")

    jmeter_path = injector_agent_path + '/workload_generators/jmeter'

    response = {}
    try:
        with open(jmeter_path + '/jmeter.log','r') as f:
            logger.info("File jmeter.log found")
            response['jmeter_log'] = f.read()

    except IOError as e:
        logger.info("File jmeter.log Not Found")
        response['jmeter_log'] = ""
        pass

    try:
        with open(jmeter_path + '/summary.csv','r') as f:
            logger.info("File summary.csv found")
            response['summary_csv'] = f.read()
        
        return json.dumps(response)    

    except IOError as e:
        logger.info("File summary.csv Not Found")
        return "ERROR"


@agent.route('/prepare_thorfi_workload_jmeter', methods=['POST'])
def prepare_thorfi_workload_jmeter():

    content = request.get_json()

    logger.info("prepare_thorfi_workload_jmeter STARTED!")

    jmeter_path = injector_agent_path + '/workload_generators/jmeter'

    #flush old sumamry.csv and jmeter.log 
    try:
        with open(jmeter_path + '/jmeter.log', 'w') as f:
            logger.info("Removed old jmeter.log file OK")
            pass
    except IOError as e:
        logger.info("Removed old jmeter.log file ERROR : %s" %e)
        return "ERROR"

    try:
        with open(jmeter_path + '/summary.csv', 'w') as f:
            logger.info("Removed old summary.csv file OK")
            pass
    except IOError as e:
        logger.info("Removed old summary.csv file ERROR : %s" %e)
        return "ERROR"
        
    # generate jmx scenario file according to set parameter
    jmx_file = 'jmeter_workload.jmx'

    try:
        with open(jmeter_path + '/jmeter_default_template.jmx', 'r') as f:
            jmeter_scenario = f.read()
    
        default_jmeter_num_thread = content.get('num_thread')
        default_jmeter_wl_duration = content.get('wl_duration')

        jmeter_server_ip = content.get('jmeter_server_ip')
        jmeter_server_port = content.get('jmeter_server_port')
        jmeter_page_file_path = content.get('jmeter_page_file_path')
        jmeter_http_method = content.get('jmeter_http_method')
        jmeter_connection_timeout = content.get('jmeter_connection_timeout')
        jmeter_response_timeout = content.get('jmeter_response_timeout')
        jmeter_troughput_value = content.get('jmeter_troughput_value')
    
        jmeter_scenario = jmeter_scenario.replace('JMETER_NUM_THREADS', str(default_jmeter_num_thread))
        jmeter_scenario = jmeter_scenario.replace('JMETER_WL_DURATION', str(default_jmeter_wl_duration))
        jmeter_scenario = jmeter_scenario.replace('SERVER_IP', jmeter_server_ip)
        jmeter_scenario = jmeter_scenario.replace('SERVER_PORT', jmeter_server_port)
        jmeter_scenario = jmeter_scenario.replace('PAGE_FILE_PATH', jmeter_page_file_path)
        jmeter_scenario = jmeter_scenario.replace('HTTP_METHOD', jmeter_http_method)
        jmeter_scenario = jmeter_scenario.replace('CONNECTION_TIMEOUT', jmeter_connection_timeout)
        jmeter_scenario = jmeter_scenario.replace('RESPONSE_TIMEOUT', jmeter_response_timeout)
        jmeter_scenario = jmeter_scenario.replace('THROUGHPUT_VALUE', jmeter_troughput_value)

        logger.debug("jmeter_scenario =>>>>>>>> %s" % jmeter_scenario)

    except IOError as e:
        logger.info("ERROR : %s" %e)
        return "ERROR"

    with open(jmeter_path + '/' + jmx_file, 'w') as f:
        f.write(jmeter_scenario)

    logger.info("prepare_thorfi_workload_jmeter ENDED!")
    
    return "OK"




if __name__ == '__main__':
     
     logger.info("Injector agent running...")
     logger.info("......................host: %s" % injectorAgent.getIp())
     logger.info("......................port: %s" % injectorAgent.getPort())

     injectorAgent.run()
     
     
