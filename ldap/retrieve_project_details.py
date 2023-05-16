import json
from common import *

try:
    project_id = os.environ['LDAP_PROJECT']
    ldap_connection = initialize_ldap_connection()
    print(json.dumps(fetch_project_details_from_ldap(ldap_connection, project_id), indent=4))
    ldap_connection.unbind()
except Exception as e:
    print(json.dumps({ "error": str(e) }, indent=4))
