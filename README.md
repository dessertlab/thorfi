## <div align="center"><img src="thorfi_logo.png" alt="MarineGEO circle logo" style="height: 100px; width:100px;"/><p align="center">ThorFI: a Novel Approach for Network Fault Injection as a Service</p></div> 

This repo includes **ThorFI**, a novel fault injection solution for virtual networks in cloud computing infrastructures. ThorFI is designed to provide non-intrusive fault injection capabilities for a cloud tenant, and to isolate injections from interfering with other tenants on the infrastructure. Currently, ThorFI supports OpenStack cloud management platform.
ThorFI details are reported into the paper "_ThorFI: a Novel Approach for Network Fault Injection as a Service_" accepted for publication in Elsevier Journal of Network and Computer Applications (JNCA).

Please, cite the following paper if you use the tools for your research:

```
@article{cotroneo2022thorfi,
	title={ThorFI: A Novel Approach for Network Fault Injection as a Service}, 
	author={Domenico Cotroneo and Luigi De Simone and Roberto Natella},
	journal = {Journal of Network and Computer Applications},
	volume = {201},
	pages = {103334},
	year = {2022},
	issn = {1084-8045},
	doi = {https://doi.org/10.1016/j.jnca.2022.103334},
}
```

## Installing ThorFI

To run ThorFI, you need a working OpenStack deployment. To try the tool, we suggest installing OpenStack on a virtual machine, by adopting an all-in-one deployment (all OpenStack services are deployed within the same VM). You can refer to the following tutorial about installing an OpenStack all-in-one deployment on CentOS: https://github.com/dessertlab/OpenStack-Fault-Injection-Environment/blob/7b1dea8afb342d2087cd3e1da555ef0e66b94258/INSTALL.md. On Ubuntu, you can use 
DevStack (https://docs.openstack.org/devstack/latest/).

Depending on your OpenStack deployment, you need to install the following pre-requisites on the Controller, Compute, and Network nodes (see also https://docs.openstack.org/neutron/latest/admin/deploy.html).

- On Ubuntu 18.04:

```
# apt-get install python-pip
# pip2 install -r /path/to/ThorFI/requirements.txt
# pip2 install decorator==4.4.1 pyrsistent==0.14.0 python-keystoneclient python-novaclient python-neutronclient python-glanceclient python-heatclient
```

- On CentOS 7:

```
# yum -y install epel-release
# yum -y install python-pip
# pip2 install -r /path/to/ThorFI/requirements.txt
# pip2 install decorator==4.4.1 pyrsistent==0.14.0 python-keystoneclient python-novaclient python-neutronclient python-glanceclient python-heatclient
```

ThorFI can be installed by copying the folder on the nodes and executed as Python scripts. It can also be installed as bundled Python package. We provide a Makefile to generate executables for the ThorFI front-end and the ThorFI injector (``thorfi_agent_app`` and ``injector_agent``).

```
# pip2 install pyinstaller==3.4
# cd ~/path/to/ThorFI
# make 
```

### Running ThorFI

In order to perform network fault injections, launch ThorFI front-end agent on the Controller node, and ThorFI injection agents on all Compute and Network nodes, following your OpenStack deployment.

In the following, we assume that the Controller node is named ``controller.example``, with the OpenStack authentication service running at http://controller.example/identity/v3 .
In order to run the ThorFI front-end agent, and to make it listen on a specifc port (e.g., 7777), use the following commands:

```
//On the Controller node

# iptables -I INPUT -p tcp --dport 7777 -j ACCEPT
# python thorfi_frontend_agent.py -i controller.example -p 7777 -a http://controller.example/identity/v3
```

On all target Compute and Network nodes, launch the ThorFI injection agents (default port is 11223):

```
//On the Compute and Network nodes

# iptables -I INPUT -p tcp --dport 11223 -j ACCEPT
# cd /path/to/ThorFI/
# python injector_agent_app/injector_agent.py -i node_ip
```

Please note that <b>node\_ip</b> is the IP address of the Compute or Network host. If you run an all-in-one OpenStack deployment, the node_ip value must be set to <b>0.0.0.0</b>.

The last (optional) step is to create the ThorFI OpenStack image (you need administrator permissions) in order to run the IPerf or JMeter workload generators. You can skip this step if you don't use the workload generators provided with ThorFI.

```
# cd /path/to/ThorFI
# openstack image create --disk-format qcow2 --container-format bare --public --file thorfi_image.qcow2 thorfi_image
```

#### Injection agents

The ThorFI injection agents need to be run into every Compute and Network node, according to the needs of cloud testers. These agents are REST-based applications that wait for injection requests from the ThorFI front-end agent. 
The ThorFI front-end agent generates a __fault configuration__ to be sent to injection agents. In particular, the __fault configuration__ includes all the ``thofi_items`` and it is built upon the target virtual resource identified by the cloud tester through the ``get_network_topology`` REST API invoked by using the ThorFI dashboard or by ThorFI client.

Each ``thofi_item`` describes a network interface, and it is characterized by an __ID__ (in OpenStack the port ID), a __location__ (i.e., the physical machine (Compute or Network node) that hosts the OpenStack network port), and a __type__ (e.g., tap devices, veth pairs, Linux bridges, Open vSwitch bridges, and so on). The list of all the ``thorfi_items`` constitutes the ``thorfi_item_map`` returned from the internal method ``get_thorfi_item_list_by_id_type()`` called by the REST API ``inject_RESOURCE``. After that, the REST API ``inject_RESOURCE`` invokes the ``do_injection_thorfi_item`` method that creates a mapping between the Network/Compute node IP (e.g., this info in the OpenStack implementation is kept into ``thorfi_item['binding:host_id']``) and each target network device described by the ``thorfi_item``, by also adding the information of the network namespace ID (if exists) to which the target network device belong. The structure will look like as in the following:

```
[
    Network NODE1 IP: {
                [
                    netns_ID1: NIC_ID1,
                    netns_ID2: NIC_ID2
                ]
    }
    Network NODE2 IP: {
                [
                    netns_ID3: NIC_ID4,
                    netns_ID4: NIC_ID5
                ]
    }
    Compute NODE1 IP: {
                [ netns_ID6: NIC_ID ]
    }
]
```

After that, the ``do_injection_thorfi_item`` method iterates over each node IP, to pass the list of target network devices to the proper injection agents listening for injection requests on that IP and a specific TCP port (by default 1234).
Inside injection agents, the method ``inject_nics()`` is responsible for actually injecting the configured fault on the target NICs. This method uses the ``ip`` Linux tool to access (if needed) the proper network namespace linked with the target physical NIC.
For example, assuming that the user selected a virtual router as the target for injecting a fault consisting of 100ms of delay. In the OpenStack implementation, a virtual router consists of at least two network interfaces; thus, the ``do_injection_thorfi_item`` will send two different requests to injection agents (likely targeting the same hosting Network node) with fault configuration. Besides the fault type, intensity, pattern, and injection timing, the fault target will contain two different NICs within the same network namespace ID. The ``inject_nics()`` will run two different injection commands by using both ``ip`` and ``tc`` user-space tool, as in the following:

```
ip netns exec qrouter-XXX tc qdisc add dev qg-XXX root netem delay 100ms
ip netns exec qrouter-XXX tc qdisc add dev qr-YYY root netem delay 100ms
```



## Performing fault injections

Assuming both ThorFI front-end and the ThorFI injection agents are running, you can use the **ThorFI client** (``thorfi_client.py``) to invoke the ThorFI REST APIs in order to perform fault injections. In the following, we describe all input parameters that can be used:


**-i, --thorfi\_agent\_host**

        ThorFI front-end agent host (Controller node) IP (required).

**-p, --thorfi\_agent\_port**

        ThorFI front-end agent host (Controller node) port (required).

**-a, --auth\_url**

        This is the authentication URL used for OpenStack authentication. Default is http://localhost:5000/v3.
    
**-pi, --project\_id**

        The OpenStack project id on which ThorFI front-end agent can retrieve the information about tenants.

**-rt, --resource\_type**

        The target network resource type. In the OpenStack implementation network, subnet, router, floatingip, and port are the supported resource types.

**-ri, --resource\_id**

        The target network resource ID.
    
**-f, --fault\_type**

        The fault type to be injected. In the current implementation, ThorFI supports delay, loss, corrupt, duplicate, bottleneck fault types.

**-fa, --fault\_args**

        The fault arguments to be specified according to the fault type. 
            - delay: the amount of delay in ms
            - loss: percentage of packet drop;
            - corrupt: the percentage of packet subject to random noise;
            - duplicate: the percentage of packets duplicated before queuing them.
            - bottleneck: the Token Bucket Filter (TBF) rate.

**-prtime, --pre\_injection\_time**

**-itime, --injection\_time**

**-pitime, --post\_injection\_time**

        The pre-injection, injection, and post-injection time in seconds.


### Injection of packet delays
In this example, we inject a delay of 1s on traffic on the __network__ resource with ID 175aa2c7-0f5c-49f6-9c9e-4f4f9c2f589a. We set the duration of the pre-injection, injection, and post-injection phases respectively to use 0s, 5s, and 0s (fault injection is triggered immediately, and lasts for 5 seconds).

```
# python thorfi_client.py -i controller.example -p 7777 -a http://controller.example/identity/v3 -pi admin -d tenant -rt network -ri 175aa2c7-0f5c-49f6-9c9e-4f4f9c2f589a -f delay -fa 1000ms -prtime 0 -itime 5 -pitime 0
```

### Injection of packet losses

In this example, we inject packet losses on 75% of the traffic flowing through the __router__ resource with ID be88692c-d532-4e49-92eb-a948064d0a23. We use the default configuration for the injection timing (0s, 20s, and 0s, respectively for pre-injection, injection, and post-injection phases).

```
# python thorfi_client.py -i controller.example -p 7777 -a http://controller.example/identity/v3 -pi admin -d tenant -rt router -ri be88692c-d532-4e49-92eb-a948064d0a23 -f loss -fa '75%'
```

### Injection of packet corruptions

In this example, we inject packet corruptions on 50% of the traffic flowing through the __router__ resource with ID be88692c-d532-4e49-92eb-a948064d0a23. The corruption is a single-bit error at a random offset in the packet. We use the default configuration for the injection timing.

```
# python thorfi_client.py -i controller.example -p 7777 -a http://controller.example/identity/v3 -pi admin -d tenant -rt router -ri be88692c-d532-4e49-92eb-a948064d0a23 -f corrupt -fa '50%'
```

## ThorFI API documentation

In the following, is reported the documentation of the main ThorFI APIs.

### **/get\_network\_topology**

**Method**: POST

**Description**: This API retrieves information about virtual network resources that are potential targets for injections, including their topology and IDs. The virtual resources will be posted to dashboard that renders the obtained topology.

**Error response messagge**: 403, 501

**Raises:** No exceptions.


### **/start\_tests**

**Method**: POST

**Description**: Reads from ThorFI database the list of tests to execute for the specific user and checks for each test if it is in a 'completed' state; if not it executes the test by calling 'inject_RESOURCE' function according to the fault configuration

**POST parameters**:

- *pre\_injection\_time*
- *injection\_time*
- *post\_injection\_time*
		
 The pre-injection, injection, and post-injection time in seconds.

- *campaign\_name*: Name of fault injection campaign to start


### **/stop\_tests**

**Method**: POST

**Description**: Tries to stop the current fault injection campaign.

**POST parameters**:

- *campaign\_name*: Name of fault injection campaign to stop

**Error response messagge**: 404, 501


### **/status\_tests**

**Method**: POST

**Description**: Gets current status of running fault injection campaign.

**POST parameters**:

- *campaign\_name*: Name of fault injection campaign to start

**Error response messagge**: 404

### _**/inject\_RESOURCE**_ API class

The inject\_RESOURCE APIs are used to request injection actions towards injection agents. Each API in this class is a POST with the following parameters:

- thorfi\_item\_id
- fault\_pattern
- fault\_pattern\_args
- fault\_target\_traffic
- fault\_target\_protocol
- fault\_target\_dst\_ports
- fault\_target\_src\_ports
- fault\_type
- fault\_args
- pre\_injection\_time
- injection\_time
- post\_injection\_time
   
The details about each parameter is specified in the section "Performing fault injections. In the following, the details about the APIs in this class.


### **/inject\_network**

**Method**: POST

**Description**: API for injecting faults into resource 'network' of neutron We perform injection for each port linked to the given network name.
    
**Error response messagge**: ERROR 

**Raises:** ``ThorFINetworkNotFoundException``, if a network resource is not found.


### **/inject\_floatingip**

**Method**: POST

**Description**: API for injecting faults into resource 'floatingip' of neutron. ThorFI performs injection for each port linked to the given network name.

**Error response messagge**: ERROR 

**Raises:** ``ThorFIFloatingIPException``, if a floatingip resource is not found.



### **/inject\_subnet**


**Method**: POST

**Description**: API for injecting faults into resource 'subnet' of neutron. ThorFI performs injection for each port linked to the linked 'network' resource for the 'subnet' name.

**Error response messagge**: ERROR 

**Raises:** ``ThorFISubnetNotFoundException``, if a network resource is not found.


### **/inject\_router**

**Method**: POST

**Description**: REST API for injecting faults into resource 'router' of neutron. ThorFI perform injection for each port linked to the given router name.
    
**Error response messagge**: ERROR 

**Raises:** ``ThorFIRouterNotFoundException``, if a router resource is not found.
 

### **/inject\_port**

**Method:** POST

**Description:** REST API for injecting faults into resource 'port' of neutron. ThorFI perform injection for the port specified in 'thorfi\_item\_id'.
    
**Error response messagge**: ERROR 

**Raises:** ``ThorFIPortNotFoundException``, if a port resource is not found.
