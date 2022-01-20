import threading
import sys
import shutil
import traceback
import requests
import json as JSON
import logging

from utils.thorfi_ssh_util import *
from utils.thorfi_ping_utils import *

class ThorFIWorkloadThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)
 
    def run(self):
        self._target(*self._args)

class ThorFIWorkload():

    def __init__(self, thorfi_log_file=None, workload_type=None, workload_params=None, thorfi_stack_id=None, thorfi_stack_outputs=None, thorfi_key_path=None, thorfi_app_dir=None):

        self.thorfi_log_file = thorfi_log_file
        self.workload_type = workload_type
        self.workload_params = workload_params
        self.thorfi_stack_id = thorfi_stack_id
        self.thorfi_stack_outputs = thorfi_stack_outputs
        self.thorfi_key_path = thorfi_key_path

        if getattr(sys, "frozen", False):
            executable = sys.executable
            self.thorfi_app_dir = os.path.dirname(executable)
        else:
            executable = __file__
            self.thorfi_app_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(executable)), os.pardir))

    def getThorFIWorkloadThorFIAppDir(self):
        return self.thorfi_app_dir

    def setThorFIWorkloadType(self, workload_type):
        self.workload_type = workload_type

    def getThorFIWorkloadType(self):
          return self.workload_type

    def setThorFIWorkloadParams(self, workload_params):
          self.workload_params = workload_params

    def getThorFIWorkloadParams(self):
          return self.workload_params

    def setThorFIStackID(self, thorfi_stack_id):
          self.thorfi_stack_id = thorfi_stack_id

    def getThorFIStackID(self):
          return self.thorfi_stack_id

    def setThorFIStackOutput(self, thorfi_stack_outputs):
          self.thorfi_stack_outputs = thorfi_stack_outputs

    def getThorFIStackOutput(self):
          return self.thorfi_stack_outputs

    def setThorFIKeyPath(self, thorfi_key_path):
          self.thorfi_key_path = thorfi_key_path

    def getThorFIKeyPath(self):
          return self.thorfi_key_path

    def getThorFIWorkloadLogger(self):
          return self.logger

    def setThorFIWorkloadLogger(self, logger):
          self.logger = logger

    def check_instances_reachability(self, ips_lists, max_retries, logger):

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


    def get_iperf_instances_ips(self, stack_outputs):

        iperf_server_public_ip = None
        iperf_client_public_ip = None

        for el in stack_outputs:

            if el['output_key'] in 'iperf_server_public_ip':
                iperf_server_public_ip = el['output_value']
            elif el['output_key'] in 'iperf_client_public_ip':
                iperf_client_public_ip = el['output_value']

        return iperf_server_public_ip, iperf_client_public_ip


    def get_jmeter_instances_ips(self, stack_outputs):
        
        jmeter_client_public_ip = None

        for el in stack_outputs:
            if el['output_key'] in ['jmeter_client_public_ip']:
                jmeter_client_public_ip = el['output_value']

        return jmeter_client_public_ip

 
    def save_logs_phy(self, test_id, test_dir, logger):

        logger.info("ThorFI Workload saving STARTED!")

        try:
            shutil.rmtree(test_dir)
            logger.info("Test dir '%s' removed" % test_dir)
        except:
            pass

        logger.info("Test dir '%s' creation..." % test_dir)
        os.makedirs(test_dir)
      
        thorfi_key_path = self.getThorFIKeyPath()

        workload_params = self.getThorFIWorkloadParams()

        default_injector_port = '11223'

        if 'iperf' in self.workload_type:
            
            client_host_ip = workload_params['iperf_client_ip']
            server_host_ip = workload_params['iperf_server_ip']

            try:
              req_to_inject = requests.post('http://' + client_host_ip + ':' + default_injector_port + '/save_logs_iperf', json={'role' : 'client'})
              logger.info("iperf_client_log saved")
              with open(test_dir + '/iperf_client.log','w') as f:
                f.write(JSON.loads(req_to_inject.text))
            
            except requests.exceptions.ConnectionError as e:
              logger.warning("Impossible to reach client_iperf on node: %s...skip it" % client_host_ip)
              pass

            try:
              req_to_inject = requests.post('http://' + server_host_ip + ':' + default_injector_port + '/save_logs_iperf', json={'role' : 'server'})
              logger.info("iperf_server_log saved")
              with open(test_dir + '/iperf_server.log','w') as f:
                f.write(JSON.loads(req_to_inject.text))

            except requests.exceptions.ConnectionError as e:
              logger.warning("Impossible to reach server_iperf on node: %s...skip it" % server_host_ip)
              pass


        elif 'jmeter' in self.workload_type:

            client_host_ip = workload_params['jmeter_client_ip']

            try:
              req_to_inject = requests.get('http://' + client_host_ip + ':' + default_injector_port + '/save_logs_jmeter')
              
              with open(test_dir + '/jmeter.log', 'w') as f:
                f.write(JSON.loads(req_to_inject.text)['jmeter_log'])

              with open(test_dir + '/summary.csv','w') as f:
                f.write(JSON.loads(req_to_inject.text)['summary_csv'])

            except requests.exceptions.ConnectionError as e:
              logger.warning("Impossible to reach client_jmeter on node: %s...skip it" % client_host_ip)

        logger.info("ThorFI Workload saving ENDED!")



    def save_logs(self, test_id, test_dir, logger):

        logger.info("ThorFI Workload saving STARTED!")

        try:
            shutil.rmtree(test_dir)
            logger.info("Test dir '%s' removed" % test_dir)
        except:
            pass

        logger.info("Test dir '%s' creation..." % test_dir)
        os.makedirs(test_dir)


        #NOTE: support only iperf and jmeter now
      
        thorfi_key_path = self.getThorFIKeyPath()

        #TODO: for now we save logs in thorfiAgent.getThorFIappDirPath(), but we need to save logs into Campaign directory
      
        if 'iperf' in self.workload_type:
          
            iperf_client_log_path = "/home/thorfi/iperf_client.log"
            #iperf_client_logs_regex = "/home/thorfi/iperf_client_*"
            iperf_server_log_path = "/home/thorfi/iperf_server.log"

            #get thorfi_stack_id and from it obtain floating ips to start iperf wl commands
            thorfi_stack_id = self.getThorFIStackID()
            workload_params = self.getThorFIWorkloadParams()
      
            stack_outputs = self.getThorFIStackOutput()

            iperf_server_public_ip, iperf_client_public_ip = self.get_iperf_instances_ips(stack_outputs)

            self.check_instances_reachability([iperf_server_public_ip, iperf_client_public_ip], 120, logger)

            time.sleep(3)

            ssh_client_session = ssh_connect(iperf_client_public_ip, 'thorfi', thorfi_key_path)
            ssh_server_session = ssh_connect(iperf_server_public_ip, 'thorfi', thorfi_key_path)

            # save workload logs in test_dir
            with SCPClient(ssh_client_session.get_transport()) as scp:
                scp.get(iperf_client_log_path, test_dir)
            
            '''
            # save client logs
            stdin, stdout, stderr = ssh_client_session.exec_command('ls ' + iperf_client_logs_regex)
            result = stdout.read().split()
            with SCPClient(ssh_client_session.get_transport()) as scp:
                for log_file in result:
                    scp.get(log_file, test_dir)
            '''

            # save server log
            with SCPClient(ssh_server_session.get_transport()) as scp:
                scp.get(iperf_server_log_path, test_dir)

        elif 'jmeter' in self.workload_type:
            
            jmeter_client_log_path = "/home/thorfi/jmeter.log"
            jmeter_client_summary_path = "/home/thorfi/summary.csv"

            #get thorfi_stack_id and from it obtain floating ips to start jmeter wl commands
            thorfi_stack_id = self.getThorFIStackID()
            workload_params = self.getThorFIWorkloadParams()

            stack_outputs = self.getThorFIStackOutput()

            jmeter_client_public_ip = self.get_jmeter_instances_ips(stack_outputs)

            self.check_instances_reachability([jmeter_client_public_ip], 120, logger)

            time.sleep(3)

            ssh_client_session = ssh_connect(jmeter_client_public_ip, 'thorfi', thorfi_key_path)

            # save client jmeter.log
            with SCPClient(ssh_client_session.get_transport()) as scp:
                scp.get(jmeter_client_log_path, test_dir)

            # save client summary.csv
            with SCPClient(ssh_client_session.get_transport()) as scp:
                scp.get(jmeter_client_summary_path, test_dir)

        logger.info("ThorFI Workload saving ENDED!")

    
    def prepare_thorfi_workload_instances_phy(self, logger):

        try:


            logger.info("ThorFI prepare_thorfi_workload_instances_phy STARTED!")

            thorfi_key_path = self.getThorFIKeyPath()

            workload_params = self.getThorFIWorkloadParams()

            default_injector_port = '11223'

            if 'iperf' in self.workload_type:
                
                client_host_ip = workload_params['iperf_client_ip']
                server_host_ip = workload_params['iperf_server_ip']

                try:
                  req_to_inject = requests.post('http://' + client_host_ip + ':' + default_injector_port + '/prepare_thorfi_workload_iperf', json={'role' : 'client'})

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach client_iperf on node: %s...skip it" % client_host_ip)
                  pass

                try:
                  req_to_inject = requests.post('http://' + server_host_ip + ':' + default_injector_port + '/prepare_thorfi_workload_iperf', json={'role' : 'server'})

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach server_iperf on node: %s...skip it" % server_host_ip)
                  pass


            elif 'jmeter' in self.workload_type:

                host_ip = workload_params['jmeter_client_ip']

                default_jmeter_num_thread = 10
                default_jmeter_wl_duration = 600

                jmeter_server_ip = workload_params['jmeter_server_ip']
                jmeter_server_port = workload_params['jmeter_server_port']
                jmeter_page_file_path = workload_params['jmeter_page_file_path']
                jmeter_http_method = workload_params['jmeter_http_method']
                jmeter_connection_timeout = workload_params['jmeter_connection_timeout']
                jmeter_response_timeout = workload_params['jmeter_response_timeout']
                jmeter_troughput_value = workload_params['jmeter_troughput_value']
        
                try:
                  jmeter_conf_params = {
                                        'num_thread' : default_jmeter_num_thread,
                                        'wl_duration' : default_jmeter_wl_duration,
                                        'jmeter_server_ip' : jmeter_server_ip,
                                        'jmeter_server_port' : jmeter_server_port,
                                        'jmeter_page_file_path' : jmeter_page_file_path,
                                        'jmeter_http_method' : jmeter_http_method,
                                        'jmeter_connection_timeout' : jmeter_connection_timeout,
                                        'jmeter_response_timeout' : jmeter_connection_timeout,
                                        'jmeter_troughput_value' : jmeter_troughput_value
                                      }

                  req_to_inject = requests.post('http://' + host_ip + ':' + default_injector_port + '/prepare_thorfi_workload_jmeter', json=jmeter_conf_params)
            
                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach injector agent on node: %s...skip it" % host_ip)
                  pass 
              
            logger.info("ThorFI prepare_thorfi_workload_instances ENDED!")


        except Exception as ex:

            logger.error("Exceptions during prepare_thorfi_workload_instances_phy!")
            logger.error("Raised exception %s" % ex)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)

            return "ERROR"



    def prepare_thorfi_workload_instances(self, logger):

        """
            prepare_thorfi_workload_instances makes some setup before starting the actual workload.
            1. flush log file
            2....
        """
        try:


            logger.info("ThorFI prepare_thorfi_workload_instances STARTED!")

            #NOTE: support only iperf now
          
            thorfi_key_path = self.getThorFIKeyPath()
            
            if 'iperf' in self.workload_type:
              
                '''
                #remove old generated iperf script client-side
                iperf_client_script_path = self.getThorFIWorkloadThorFIAppDir() + '/iperf_client_script.sh'
                shutil.rmtree(iperf_client_script_path)
                '''

                stack_outputs = self.getThorFIStackOutput()
          
                iperf_server_public_ip, iperf_client_public_ip = self.get_iperf_instances_ips(stack_outputs)
                
                self.check_instances_reachability([iperf_server_public_ip, iperf_client_public_ip], 120, logger)

                time.sleep(3)

                ssh_client_session = ssh_connect(iperf_client_public_ip, 'thorfi', thorfi_key_path)
                ssh_server_session = ssh_connect(iperf_server_public_ip, 'thorfi', thorfi_key_path)

                #remove old log files
                exit_code_server = ssh_command(ssh_server_session, 'rm -rf /home/thorfi/*')
                logger.info("Removed old log file on server (exit code %s)" % (exit_code_server))
         
                exit_code_client = ssh_command(ssh_client_session, 'rm -rf /home/thorfi/*')
                logger.info("Removed old log file on client (exit code %s)" % (exit_code_client))

            elif 'jmeter' in self.workload_type:

                '''
                    flush summary.csv file
                    flush jmeter.log file
                '''
                stack_outputs = self.getThorFIStackOutput()
                
                jmeter_client_public_ip = self.get_jmeter_instances_ips(stack_outputs)

                self.check_instances_reachability([jmeter_client_public_ip], 120, logger)

                time.sleep(3)

                ssh_client_session = ssh_connect(jmeter_client_public_ip, 'thorfi', thorfi_key_path)

                #flush or create summary.csv file
                exit_code_client_1 = ssh_command(ssh_client_session, '> /home/thorfi/summary.csv')

                #flush or create jmeter.log

                exit_code_client_2 = ssh_command(ssh_client_session, '> /home/thorfi/jmeter.log')

                logger.info("Removed old jmeter.log file on client (exit code %s)" % (exit_code_client_2))
                logger.info("Removed old summary.csv file on client (exit code %s)" % (exit_code_client_1))

                # generate jmx scenario file according to set parameter
                jmx_file = 'jmeter_workload.jmx'
          
                with open(self.getThorFIWorkloadThorFIAppDir() + '/jmeter_default_template.jmx', 'r') as f:
                    jmeter_scenario = f.read()

                default_jmeter_num_thread = 10
                default_jmeter_wl_duration = 600

                wl_param = self.getThorFIWorkloadParams()

                jmeter_server_ip = wl_param['jmeter_server_ip']
                jmeter_server_port = wl_param['jmeter_server_port']
                jmeter_page_file_path = wl_param['jmeter_page_file_path']
                jmeter_http_method = wl_param['jmeter_http_method']
                jmeter_connection_timeout = wl_param['jmeter_connection_timeout']
                jmeter_response_timeout = wl_param['jmeter_response_timeout']
                jmeter_troughput_value = wl_param['jmeter_troughput_value']
                
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

                with open(self.getThorFIWorkloadThorFIAppDir() + '/' + jmx_file, 'w') as f:
                    f.write(jmeter_scenario)
          
                with SCPClient(ssh_client_session.get_transport()) as scp:
                    scp.put(self.getThorFIWorkloadThorFIAppDir() + '/' + jmx_file, '/home/thorfi/')

                logger.debug("Copied jmx_file %s under remote /home/thorfi" % jmx_file)
                with SCPClient(ssh_client_session.get_transport()) as scp:
                    scp.put(self.getThorFIWorkloadThorFIAppDir() + '/jmeter_conf/hosts', '/home/thorfi/')

                logger.debug("Copied hosts under remote /home/thorfi")

                with SCPClient(ssh_client_session.get_transport()) as scp:
                    scp.put(self.getThorFIWorkloadThorFIAppDir() + '/move_hosts_file.sh', '/home/thorfi/')

                logger.debug("Copied move_hosts_file.sh under remote /home/thorfi")

                #execute move_hosts_file to move hosts file under /etc/
                exit_code = ssh_command(ssh_client_session, 'sudo /home/thorfi/move_hosts_file.sh')
                logger.debug("Executed (exit code %s) move_hosts_file.sh remotely" % exit_code)

            logger.info("ThorFI prepare_thorfi_workload_instances ENDED!")

        except Exception as ex:

            logger.error("Exceptions during prepare_thorfi_workload_instances!")
            logger.error("Raised exception %s" % ex)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)

            return "ERROR"

    def start_thorfi_workload_phy(self, logger):

        try:


            logger.info("ThorFI Workload STARTED!")
          
            logger.info("workload type %s" % self.workload_type)

            thorfi_key_path = self.getThorFIKeyPath()
            
            logger.info("thorfi_key_path  %s" % thorfi_key_path)

            workload_params = self.getThorFIWorkloadParams()

            default_injector_port = '11223'

            if 'iperf' in self.workload_type:

                client_host_ip = workload_params['iperf_client_ip']
                server_host_ip = workload_params['iperf_server_ip']

                iperf_server_port = workload_params['iperf_server_port']
                iperf_bandwidth = workload_params['iperf_bandwidth'] + 'M'
                iperf_protocol = workload_params['iperf_protocol']

                iperf_client_conf_params = {
                                            'role' : 'client',
                                            'server_host_ip' : server_host_ip,
                                            'iperf_server_port' : iperf_server_port,
                                            'iperf_bandwidth' : iperf_bandwidth,
                                            'iperf_protocol' : iperf_protocol
                                            }

                iperf_server_conf_params = { 
                                            'role' : 'server',
                                            'iperf_server_port' : iperf_server_port
                                            }


                try:
                  req_to_inject = requests.post('http://' + server_host_ip + ':' + default_injector_port + '/start_thorfi_workload_iperf', json=iperf_server_conf_params)

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach server_iperf on node: %s...skip it" % server_host_ip)
                  pass

                #wait for server start
                logger.info("Wait 1 s for iperf server to be run...")
                time.sleep(1)

                try:
                  req_to_inject = requests.post('http://' + client_host_ip + ':' + default_injector_port + '/start_thorfi_workload_iperf', json=iperf_client_conf_params)

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach client_iperf node: %s...skip it" % client_host_ip)
                  pass


            elif 'jmeter' in self.workload_type:
                
                client_host_ip = workload_params['jmeter_client_ip']

                try:
                  req_to_inject = requests.get('http://' + client_host_ip + ':' + default_injector_port + '/start_thorfi_workload_jmeter')

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach client_jmeter node: %s...skip it" % client_host_ip)
                  pass

                jmeter_start_max_retry = 10

                count = 0
                jmeter_NOT_start = True

                while (count <= jmeter_start_max_retry and jmeter_NOT_start):
                  try:
                    req_to_inject = requests.get('http://' + client_host_ip + ':' + default_injector_port + '/check_thorfi_workload_jmeter')
                    exit_code_client_jmeter_start_check = JSON.loads(req_to_inject.text)
                    
                    if int(exit_code_client_jmeter_start_check):
                      count += 1
                      logger.debug("In jmeter client, the workload has not started yet : retry %s ..." % count)
                    else:
                      jmeter_NOT_start = False
                      logger.info("In jmeter client, the workload is started !!!")

                    time.sleep(1)

                  except requests.exceptions.ConnectionError as e:
                    logger.warning("Impossible to reach client_jmeter node: %s...skip it" % client_host_ip)
                    pass

                if ( jmeter_NOT_start ):
                  logger.error("In jmeter client, the workload has not started !!! Raised Exception")
                  raise Exception

        except Exception as ex:

            logger.error("Exceptions during thorfi workload execution!")
            logger.error("Raised exception %s" % ex)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)

            return "ERROR"


    def start_thorfi_workload(self, logger):

        """
            'start_thorfi_workload' must run specific network workload for the specified 'workload_type'
            In the following, we specify for each workload type the steps to be made.

            iperf:

                Client-side command:
                  
                  # iperf -c $FLOATING_IP_SERVER -p $SERVER_PORT -t 0 -b 1M

                Server-side command:

                  # iperf -s -p $SERVER_PORT
        """

        try:


            logger.info("ThorFI Workload STARTED!")

            #NOTE: support only iperf now
          
            logger.info("workload type %s" % self.workload_type)

            thorfi_key_path = self.getThorFIKeyPath()
            
            logger.info("thorfi_key_path  %s" % thorfi_key_path)

            if 'iperf' in self.workload_type:
              
                iperf_command = "iperf3"
                #iperf_client_log_path = "/home/thorfi/iperf_client_${retry}.log"
                iperf_client_log_path = "/home/thorfi/iperf_client.log"
                iperf_server_log_path = "/home/thorfi/iperf_server.log"

                #get thorfi_stack_id and from it obtain floating ips to start iperf wl commands
                thorfi_stack_id = self.getThorFIStackID()
                workload_params = self.getThorFIWorkloadParams()
          
                stack_outputs = self.getThorFIStackOutput()
        
                iperf_server_public_ip, iperf_client_public_ip = self.get_iperf_instances_ips(stack_outputs)

                self.check_instances_reachability([iperf_server_public_ip, iperf_client_public_ip], 120, logger)

                time.sleep(3)

                iperf_server_port = workload_params['iperf_server_port']
                iperf_bandwidth = workload_params['iperf_bandwidth'] + 'M'
                iperf_protocol = workload_params['iperf_protocol']

                #start workload
                ssh_client_session = ssh_connect(iperf_client_public_ip, 'thorfi', thorfi_key_path)
                ssh_server_session = ssh_connect(iperf_server_public_ip, 'thorfi', thorfi_key_path)

                #start actual workload
                
                if 'udp' in iperf_protocol:
                    client_command = 'nohup ' + iperf_command + ' -c ' + iperf_server_public_ip + ' -p ' + iperf_server_port + ' -t 0 -b ' + iperf_bandwidth + ' -f k -u -J --logfile ' + iperf_client_log_path + ' &'
                else:
                    client_command = 'nohup ' + iperf_command + ' -c ' + iperf_server_public_ip + ' -p ' + iperf_server_port + ' -t 0 -b ' + iperf_bandwidth + ' -f k -J --logfile ' + iperf_client_log_path + ' &'
                       
                server_command = 'nohup ' + iperf_command + ' -s -p ' + iperf_server_port + ' -f k -J --logfile ' + iperf_server_log_path + ' &'
                    
                exit_code_server = ssh_command(ssh_server_session, server_command) 
                logger.info("Sent server iperf command: %s (exit code %s)" % (server_command, exit_code_server))
         
                #wait for server start
                logger.info("Wait 1 s for iperf server to be run...")
                time.sleep(1)

                exit_code_client = ssh_command(ssh_client_session, client_command)
                logger.info("Sent client iperf command: %s (exit code %s)" % (client_command, exit_code_client)) 

            elif 'jmeter' in self.workload_type:

                jmx_file = '/home/thorfi/jmeter_workload.jmx'
                jmeter_command = '/apache-jmeter-5.0/bin/./jmeter.sh -n -t ' + jmx_file + ' -l summary.csv'
                jmeter_client_log_path = "/home/thorfi/jmeter.log"
                jmeter_client_summary_path = "/home/thorfi/summary.csv"

                jmeter_start_max_retry = 180
                #jmeter_start_check_command = 'if [ -s summary.csv ]; then exit 0; else exit 1; fi'
                jmeter_start_check_command = 'cat jmeter.log | grep "Sample TimeStamps are START times" > /dev/null 2>&1; if [ $? -eq 1 ]; then exit 1; else exit 0; fi'
                #get thorfi_stack_id and from it obtain floating ips to start iperf wl commands
                thorfi_stack_id = self.getThorFIStackID()
                workload_params = self.getThorFIWorkloadParams()
          
                stack_outputs = self.getThorFIStackOutput()

                jmeter_client_public_ip = self.get_jmeter_instances_ips(stack_outputs)

                self.check_instances_reachability([jmeter_client_public_ip], 120, logger)

                time.sleep(3)

                #start workload
                ssh_client_session = ssh_connect(jmeter_client_public_ip, 'thorfi', thorfi_key_path)

                client_command = 'nohup ' + jmeter_command + ' &'

                exit_code_client = ssh_command(ssh_client_session, client_command)
                logger.info("Sent client jmeter command: %s (exit code %s)" % (client_command, exit_code_client))

                count = 0
                jmeter_NOT_start = True
                while (count <= jmeter_start_max_retry and jmeter_NOT_start):

                    exit_code_client_jmeter_start_check = ssh_command(ssh_client_session, jmeter_start_check_command)
                    logger.debug("Sent client jmeter command: %s (exit code %s)" % (jmeter_start_check_command, exit_code_client_jmeter_start_check))
                    if exit_code_client_jmeter_start_check:
                        count += 1
                        logger.debug("In jmeter client, the workload has not started yet : retry %s ..." % count)
                    else:
                        jmeter_NOT_start = False
                        logger.info("In jmeter client, the workload is started !!!")

                    time.sleep(1) 

                if ( jmeter_NOT_start ):
                    logger.error("In jmeter client, the workload has not started !!! Raised Exception")
                    raise Exception



        except Exception as ex:

            logger.error("Exceptions during thorfi workload execution!")
            logger.error("Raised exception %s" % ex)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)

            return "ERROR"

    def wait_for_thorfi_workload_completion(self, duration=30):

        """
            wait_for_thorfi_workload_completion just wait for workload duration specified in 'duration'
        """

        time.sleep(duration)

    def check_vm_reachability(self):
        
        stack_outputs = self.getThorFIStackOutput()

        if 'iperf' in self.workload_type:
            
            iperf_server_public_ip, iperf_client_public_ip = self.get_iperf_instances_ips(stack_outputs) 

            self.check_instances_reachability([iperf_server_public_ip, iperf_client_public_ip], 120, logger)

        elif 'jmeter' in self.workload_type:
            
            jmeter_client_public_ip = self.get_jmeter_instances_ips(stack_outputs)

            self.check_instances_reachability([jmeter_client_public_ip], 120, logger)


    def stop_thorfi_workload_phy(self, logger):

        try:

            logger.info("STARTED ThorFI Workload STOPPING...")
            thorfi_key_path = self.getThorFIKeyPath()

            workload_params = self.getThorFIWorkloadParams()

            default_injector_port = '11223'

            if 'iperf' in self.workload_type:
                
                client_host_ip = workload_params['iperf_client_ip']
                server_host_ip = workload_params['iperf_server_ip']

                try:
                  req_to_inject = requests.get('http://' + client_host_ip + ':' + default_injector_port + '/stop_thorfi_workload_iperf')
                  logger.info('iperf client workload stopped')

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach client_iperf on node: %s...skip it" % client_host_ip)
                  pass

                try:
                  req_to_inject = requests.get('http://' + server_host_ip + ':' + default_injector_port + '/stop_thorfi_workload_iperf')
                  logger.info('iperf server workload stopped')

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach server_iperf on node: %s...skip it" % server_host_ip)
                  pass


            elif 'jmeter' in self.workload_type:

                client_host_ip = workload_params['jmeter_client_ip']

                try:
                  req_to_inject = requests.get('http://' + client_host_ip + ':' + default_injector_port + '/stop_thorfi_workload_jmeter')
                  logger.info('jmeter workload stopped')

                except requests.exceptions.ConnectionError as e:
                  logger.warning("Impossible to reach client_jmeter on node: %s...skip it" % client_host_ip)
                  pass

            logger.info("ThorFI Workload STOPPED!!!!!!!") 

        except Exception as ex:

            logger.error("Exceptions during stop_thorfi_workload_phy!")
            logger.error("Raised exception %s" % ex)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)

            return "ERROR"


    def stop_thorfi_workload(self, logger):

        try:


            logger.info("STARTED ThorFI Workload STOPPING...")

            thorfi_key_path = self.getThorFIKeyPath()
            
            if 'iperf' in self.workload_type:

                stack_outputs = self.getThorFIStackOutput()
       
                iperf_server_public_ip, iperf_client_public_ip = self.get_iperf_instances_ips(stack_outputs) 

                self.check_instances_reachability([iperf_server_public_ip, iperf_client_public_ip], 120, logger)

                time.sleep(3)

                #start workload
                ssh_client_session = ssh_connect(iperf_client_public_ip, 'thorfi', thorfi_key_path)
                ssh_server_session = ssh_connect(iperf_server_public_ip, 'thorfi', thorfi_key_path)

                #stop workload: in iperf we kill iperf processes
                exit_status_client, client_pid, stderr_client = ssh_command_with_out(ssh_client_session, "ps aux|grep iperf |grep -v grep|awk '{print $2}'")
                exit_status_server, server_pid, stderr_server = ssh_command_with_out(ssh_server_session, "ps aux|grep iperf |grep -v grep|awk '{print $2}'")
              
                exit_status_client = ssh_command(ssh_client_session, "sudo kill -SIGTERM " + client_pid)
                exit_status_server = ssh_command(ssh_server_session, "sudo kill -SIGTERM " + server_pid)

            elif 'jmeter' in self.workload_type:

                jmeter_command = '/apache-jmeter-5.0/bin/./shutdown.sh'

                stack_outputs = self.getThorFIStackOutput()

                jmeter_client_public_ip = self.get_jmeter_instances_ips(stack_outputs)

                self.check_instances_reachability([jmeter_client_public_ip], 120, logger)

                time.sleep(3)

                #start workload
                ssh_client_session = ssh_connect(jmeter_client_public_ip, 'thorfi', thorfi_key_path)

                #stop workload: in jmeter we launch stoptest.sh script
                exit_status_client = ssh_command(ssh_client_session, jmeter_command)


            logger.info("ThorFI Workload STOPPED!!!!!!!") 

        except Exception as ex:

            logger.error("Exceptions during stop_thorfi_workload!")
            logger.error("Raised exception %s" % ex)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, limit=20, file=sys.stdout)

            return "ERROR"

