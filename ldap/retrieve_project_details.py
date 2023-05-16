import json
from common import *

try:

    project_id = os.environ['LDAP_PROJECT']
    
    config = json.load(open("%s/config.json" % os.environ['ROOT']))
    
    ldap_hosts = config['LDAP_HOSTS']
    ldap_read_user = config['LDAP_READ_USER']
    ldap_read_password = config['LDAP_READ_PASSWORD']
    ldap_servers = []
    
    for ldap_server_url in ldap_hosts:
        ldap_servers.append(Server(ldap_server_url, use_ssl=True, get_info=ALL))
    
    ldap_server_pool = ServerPool(ldap_servers, FIRST, active=True, exhaust=True)
    
    ldap_connection = Connection(ldap_server_pool, ldap_read_user, ldap_read_password, auto_bind=True)
    
    if ldap_connection and ldap_connection.bound:
        print(json.dumps(fetch_project_details_from_ldap(ldap_connection, project_id), indent=4))
    
    else:
        raise Exception("LDAP initialization failed: %s" % str(ldap_connection))
    
except Exception as e:
    print(json.dumps({ "error": str(e) }, indent=4))
