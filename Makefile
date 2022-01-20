all: thorfi_frontend_agent thorfi_injector_agent

thorfi_frontend_agent: 

	pyinstaller -w --clean --onefile thorfi_frontend_agent.py --add-data './config.py:.' --paths './libs' --hiddenimport email.mime.message --hiddenimport email.mime.image --hiddenimport email.mime.text --hiddenimport email.mime.audio --hiddenimport email.mime.multipart --hiddenimport keystoneauth1 --hiddenimport keystoneauth1.identity --hiddenimport neutronclient --hiddenimport novaclient --hiddenimport novaclient.v2 --hiddenimport keystoneclient --hiddenimport glanceclient --hiddenimport glanceclient.v2 --hiddenimport heatclient --hiddenimport heatclient.v1 --hiddenimport oslo_utils --hiddenimport importlib --hiddenimport pbr --hiddenimport pbr.version --hiddenimport positional --hiddenimport debtcollector --hiddenimport debtcollector.renames
	
	mv ./dist/thorfi_frontend_agent .
	
thorfi_injector_agent: 

	pyinstaller -w --clean --onefile injector_agent_app/injector_agent.py --add-data './config.py:.' --paths './libs' --hiddenimport email.mime.message --hiddenimport email.mime.image --hiddenimport email.mime.text --hiddenimport email.mime.audio --hiddenimport email.mime.multipart --hiddenimport keystoneauth1 --hiddenimport keystoneauth1.identity --hiddenimport neutronclient --hiddenimport novaclient --hiddenimport novaclient.v2 --hiddenimport keystoneclient --hiddenimport glanceclient --hiddenimport glanceclient.v2 --hiddenimport heatclient --hiddenimport heatclient.v1 --hiddenimport oslo_utils --hiddenimport importlib --hiddenimport pbr --hiddenimport pbr.version --hiddenimport positional --hiddenimport debtcollector --hiddenimport debtcollector.renames

	mv ./dist/injector_agent .

clean_master_agent:
	rm -rf ./dist
	rm -rf ./build
	rm -rf thorfi_frontend_agent.spec
	rm -rf thorfi_frontend_agent

clean_injector_agent:
	rm -rf ./dist
	rm -rf ./build
	rm -rf injector_agent.spec
	rm -rf injector_agent
clean:
	rm -rf ./dist
	rm -rf ./build
	rm -rf *.spec
	rm -rf thorfi_frontend_agent
	rm -rf injector_agent
