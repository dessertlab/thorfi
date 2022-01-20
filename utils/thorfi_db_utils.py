import sqlalchemy as db

from thorfi_db_utils_exceptions import *
from thorfi.models import *

def setCampaignFromUser(username, campaign_name):

	try:
		campaign = Campaign.query.filter_by(user_username=username, campaign_name=campaign_name).first()	

		if not campaign:
			#logger.debug("In setCampaignFromUser the campaign % not found for user %. Creating ...." % (campaign_name, username))
			
			new_campaign = Campaign(campaign_name=campaign_name, user_username=username)

			db.session.add(new_campaign)
			db.session.commit()


		else:
			raise ThorFIdbDuplicateCampaignException(username, campaign_name)

	except Exception:

		raise



def getCampaignListFromUser(username):

	resp = []

	try:
		campaign_list = Campaign.query.filter_by(user_username=username).all()

		for campaign in campaign_list:
			resp.append(campaign.campaign_name)

		return resp

	except Exception:
		raise


def getCampaignID(username, campaign_name):

	try:
		campaign = Campaign.query.filter_by(user_username=username, campaign_name=campaign_name).first()

		return campaign.get_id()

	except Exception:
		raise 


def setTestsFromCampaign(campaign_id, test_list):

	""" 
		This function save/update fips list for the specific campaign_id:
			- if a new fault has been added to fips list => add(new_fault)
			- if a old fault has been removed from fips list => remove(old_fault)

		A fip is defined such as "new" if it is in the index_fips_list but it isn't in the db_fips_list. 

		A fip is defined such as "old" if it is in the db_fips_list but it isn't in the index_fips_list.

	"""


	
	index_fips_list = []

	for fip in test_list:

		index_fips_list.append(fip.split('#'))


	try:
		#Remove from db the unused fips
		db_fips_list = getObjTestsFromCampaign(campaign_id)

		for old_fip in db_fips_list:

			#from Test.object to list
			old_fip_array = []
			old_fip_array.append(old_fip.index)
			old_fip_array.append(old_fip.domain)
			old_fip_array.append(old_fip.resource_type)
			old_fip_array.append(old_fip.resource_name)
			old_fip_array.append(old_fip.resource_faultID)
			old_fip_array.append(old_fip.fault_name)
			old_fip_array.append(old_fip.fault_args)
			old_fip_array.append(old_fip.fault_description)
			old_fip_array.append(old_fip.fault_pattern_name)
			old_fip_array.append(old_fip.fault_pattern_arg1)
			old_fip_array.append(old_fip.fault_pattern_arg2)
			old_fip_array.append(old_fip.fault_target_traffic_name)
			old_fip_array.append(old_fip.fault_target_traffic_protocol)
			old_fip_array.append(old_fip.fault_target_traffic_src_ports)
			old_fip_array.append(old_fip.fault_target_traffic_dest_ports)
			old_fip_array.append(old_fip.status)

			for new_fip in index_fips_list:
				if ( old_fip_array ==  new_fip ):
					#if the new_fip is already in the db => skip
					break;
			
			#if old_fip isn't in the index_fips_list => remove from db
			removed_test = Test.query.filter_by(ID=old_fip.ID).first()

			db.session.delete(removed_test)

		db.session.commit()



		#Add to db the new fips
		db_fips_list = getObjTestsFromCampaign(campaign_id)
		
		for new_fip in index_fips_list:

			for old_fip in db_fips_list:

				#from Test.object to list
				old_fip_array = []
				old_fip_array.append(old_fip.index)
				old_fip_array.append(old_fip.domain)
				old_fip_array.append(old_fip.resource_type)
				old_fip_array.append(old_fip.resource_name)
				old_fip_array.append(old_fip.resource_faultID)
				old_fip_array.append(old_fip.fault_name)
				old_fip_array.append(old_fip.fault_args)
				old_fip_array.append(old_fip.fault_description)
				old_fip_array.append(old_fip.fault_pattern_name)
				old_fip_array.append(old_fip.fault_pattern_arg1)
				old_fip_array.append(old_fip.fault_pattern_arg2)
				old_fip_array.append(old_fip.fault_target_traffic_name)
				old_fip_array.append(old_fip.fault_target_traffic_protocol)
				old_fip_array.append(old_fip.fault_target_traffic_src_ports)
				old_fip_array.append(old_fip.fault_target_traffic_dest_ports)
				old_fip_array.append(old_fip.status)

			
				if ( old_fip_array ==  new_fip ):
					#if the new_fip is already in the db => skip
					break;
			
			#if new_fip isn't in the db_fips_list => add to db
			new_test = Test( index = new_fip[0],
							domain = new_fip[1],
							resource_type = new_fip[2],
							resource_name = new_fip[3],
							resource_faultID = new_fip[4],
							fault_name = new_fip[5],
							fault_args = new_fip[6],
							fault_description = new_fip[7],
							fault_pattern_name = new_fip[8],
							fault_pattern_arg1 = new_fip[9],
							fault_pattern_arg2 = new_fip[10],
							fault_target_traffic_name = new_fip[11],
							fault_target_traffic_protocol = new_fip[12],
							fault_target_traffic_src_ports = new_fip[13],
							fault_target_traffic_dest_ports = new_fip[14],
							status = new_fip[15],
							campaign_id = campaign_id
							)

			db.session.add(new_test)
		
		db.session.commit()

		
	except Exception:
		db.session.rollback()
		raise



def getObjTestsFromCampaign(campaign_id):

	try:
		test_list = Test.query.filter_by(campaign_id=campaign_id).all()

		return test_list

	except Exception:
		raise



def getTestsFromCampaign(campaign_id):

	_test_list = []

	try:
		test_list = Test.query.filter_by(campaign_id=campaign_id).all()
		
				
		for test in test_list:
			a = []

			#a.append(test.index)
			a.append('')
			a.append(test.domain)
			a.append(test.resource_type)
			a.append(test.resource_name)
			a.append(test.resource_faultID)
			a.append(test.fault_name)
			a.append(test.fault_args)
			a.append(test.fault_description)
			a.append(test.fault_pattern_name)
			a.append(test.fault_pattern_arg1)
			a.append(test.fault_pattern_arg2)
			a.append(test.fault_target_traffic_name)
			a.append(test.fault_target_traffic_protocol)
			a.append(test.fault_target_traffic_src_ports)
			a.append(test.fault_target_traffic_dest_ports)
			a.append(test.status)

			_test_list.append(a)

		return _test_list

	except Exception:
		raise


def updateTestStatus(campaign_id, current_test_index, status):

	try:
		test = Test.query.filter_by(campaign_id=campaign_id, index=current_test_index).first()

		test.status = status

		db.session.add(test)
		db.session.commit()

	except Exception:
		db.session.rollback()
		raise



def setWL_Conf(campaign_id, wl_conf):

	
	try:

		old_wl = WL_Conf.query.filter_by(campaign_id=campaign_id).first()

		if old_wl:
			db.session.delete(old_wl)
			db.session.commit()

		new_wl = WL_Conf( 	workload_type = wl_conf['workload_type'],
							iperf_client_generator_conf = wl_conf['iperf_client_generator_conf'],
							iperf_server_generator_conf = wl_conf['iperf_server_generator_conf'],
							jmeter_client_generator_conf = wl_conf['jmeter_client_generator_conf'],
							campaign_id = campaign_id
						)

		db.session.add(new_wl)
			
		db.session.commit()

	except Exception:
		db.session.rollback()
		raise


def getWL_Conf(campaign_id):

	try:

		wl_conf_obj = WL_Conf.query.filter_by(campaign_id=campaign_id).first()

		wl_conf = {}
		
		if wl_conf_obj:
			wl_conf['workload_type'] = wl_conf_obj.workload_type
			wl_conf['iperf_client_generator_conf'] = wl_conf_obj.iperf_client_generator_conf
			wl_conf['iperf_server_generator_conf'] = wl_conf_obj.iperf_server_generator_conf
			wl_conf['jmeter_client_generator_conf'] = wl_conf_obj.jmeter_client_generator_conf

		return wl_conf

	except Exception:
		raise

def setTime_Conf(campaign_id, time_conf):

	try:
		old_time = Time_Conf.query.filter_by(campaign_id=campaign_id).first()

		if old_time:
			db.session.delete(old_time)
			db.session.commit()

		new_time = Time_Conf( 	pre_injection_time = time_conf['pre_injection_time'],
								injection_time = time_conf['injection_time'],
								post_injection_time = time_conf['post_injection_time'],
								campaign_id = campaign_id
							)

		db.session.add(new_time)
		db.session.commit()

	except Exception:
		db.session.rollback()
		raise

def getTime_Conf(campaign_id):

	try:

		time_conf_obj = Time_Conf.query.filter_by(campaign_id=campaign_id).first()

		time_conf = {}
		
		if time_conf_obj:
			time_conf['pre_injection_time'] = time_conf_obj.pre_injection_time
			time_conf['injection_time'] = time_conf_obj.injection_time
			time_conf['post_injection_time'] = time_conf_obj.post_injection_time

		else:
			time_conf['pre_injection_time'] = "5"
			time_conf['injection_time'] = "30"
			time_conf['post_injection_time'] = "5"

		return time_conf

	except Exception:
		raise



def getNet_Topology(campaign_id):

	try:
		net_topology_hash_obj = Campaign.query.filter_by(campaign_id=campaign_id).first()

		return net_topology_hash_obj.net_topology_hash

	except Exception:
		raise

def setNet_Topology(campaign_id, net_topology_hash):

	try:
		net_topology_hash_obj = Campaign.query.filter_by(campaign_id=campaign_id).first()
		
		#update hash
		net_topology_hash_obj.net_topology_hash = net_topology_hash

		db.session.add(net_topology_hash_obj)
		db.session.commit()

	except Exception:
		raise		

