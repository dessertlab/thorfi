import argparse
import time
import requests
import json
import sys
import copy

from thorfi.thorfi_exceptions import *
from utils.thorfi_utils import get_credentials_from_sources

import logging

logging.basicConfig(format='%(asctime)s.%(msecs)03d %(process)d thorfi_client %(levelname)s %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)


def GetArgs():

    tenant_resource_type_list = ['network', 'subnet', 'router', 'floatingip', 'port']
    infrastructure_resource_type_list = ['node']
    fault_type_list = ['delay', 'loss', 'corrupt', 'duplicate', 'bottleneck', 'down', 'reboot']
    all_resource_type = copy.deepcopy(tenant_resource_type_list)
    all_resource_type.extend(infrastructure_resource_type_list)

    parser = argparse.ArgumentParser(description='Process args for retrieving arguments')

    parser.add_argument('-i', '--thorfi_agent_host', required=True, action='store', help='ThorFI agent host ip')
    parser.add_argument('-p', '--thorfi_agent_port', required=True, action='store', help='ThorFI agent host port')
    
    parser.add_argument('-a', '--auth_url', required=False, action='store', default='http://localhost:5000/v3', help='ThorFI agent OpenStack auth url')
    parser.add_argument('-pi', '--project_id', required=False, action='store', help='ThorFI agent OpenStack project id ')

    parser.add_argument('-d', '--domain', required=True, action='store', choices=['tenant', 'infrastructure'], help='Domain of injection')
    parser.add_argument('-rt', '--resource_type', required=True, action='store', choices=all_resource_type, help='Target resource type')
    parser.add_argument('-ri', '--resource_id', required=True, action='store', help='Target resource name')
    parser.add_argument('-f', '--fault_type', required=True, action='store', help='Fault type [ delay | loss | corrupt | duplicate | bottleneck | down | reboot]')
    parser.add_argument('-fa', '--fault_args', required=True, action='store', help='Fault arguments (see documentation)')
    parser.add_argument('-prtime', '--pre_injection_time', required=False, default='0', action='store', help='Pre-injection time in seconds')
    parser.add_argument('-itime', '--injection_time', required=False, default='20', action='store', help='Injection time in seconds')
    parser.add_argument('-pitime', '--post_injection_time', required=False, default='0', action='store', help='Post-injection time in seconds')
    
    args = parser.parse_args()

    #check valid combination for fault_type injection
    if args.fault_type not in fault_type_list:
         logger.error("Please, you must specify right fault type [ delay | loss | corrupt | duplicate | bottleneck | down | reboot]")
         sys.exit(-1)

    #check valid combination for tenant injection
    if 'tenant' in args.domain:
        if args.resource_type not in tenant_resource_type_list:
            logger.error("Please, for tenant injection you must specify resource type in {'network' | 'router' | 'port'}")
            sys.exit(-1)

    #check valid combination for infrastructure injection
    if 'infrastructure' in args.domain:
        if args.resource_type not in infrastructure_resource_type_list:
            logger.error("Please, for tenant injection you must specify resource type in {'node'}")
            sys.exit(-1)

    return args


if __name__ == "__main__":
    
    args = GetArgs()

    domain=args.domain
    target_resource_id = args.resource_id
    target_resource_type = args.resource_type
    fault_type = args.fault_type
    fault_args = args.fault_args
    pre_injection_time = args.pre_injection_time
    injection_time = args.injection_time
    post_injection_time = args.post_injection_time

    thorfi_agent_host = args.thorfi_agent_host
    thorfi_agent_port = args.thorfi_agent_port

    fault_configuration = {'target_resource_name': target_resource_id,
                            'fault_pattern':'persistent',
                            'fault_pattern_args':'',
                            'fault_target_traffic':'any', 
                            'fault_target_protocol':'TCP',
                            'fault_target_dst_ports':'',
                            'fault_target_src_ports':'',
                            'fault_type': fault_type,
                            'fault_args': fault_args,
                            'pre_injection_time': pre_injection_time,
                            'injection_time': injection_time,
                            'post_injection_time': post_injection_time,
                            }

    # check auth
    credentials = get_credentials_from_sources()
    
    credentials.update({'project_id' : args.project_id})

    print credentials
    s = requests.Session()
    try:
        logger.info("Start authentication...")
        resp = s.post('http://' + thorfi_agent_host + ':' + thorfi_agent_port + '/authenticate_client', json=credentials)
        logger.info("Response from thorfi agent: %s" % resp)

    except:

        logger.error("Impossible to authenticate with ThorFI agent on node '%s'" % thorfi_agent_host)
        sys.exit(-1)
       
    try:

        logger.info("Start injection (mode: '%s')" % domain)
        logger.info("Fault injection config: %s" % fault_configuration)

        resp = s.post('http://' + thorfi_agent_host + ':' + thorfi_agent_port + '/inject_' + target_resource_type, json=fault_configuration) 

        logger.info("Response from thorfi agent: %s" % resp)
        logger.info("End injection")

        logger.info("Logout")
        resp = s.post('http://' + thorfi_agent_host + ':' + thorfi_agent_port + '/logout') 

    except requests.exceptions.ConnectionError as e:

        logger.error("Impossible to reach ThorFI agent on node '%s'...please start agent on that node" % thorfi_agent_host)
        sys.exit(-1)
