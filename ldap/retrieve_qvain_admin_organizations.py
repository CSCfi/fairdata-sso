import os
import json
from common import *

try:
    user_id = os.environ['LDAP_USER']
    ldap_connection = initialize_ldap_connection()
    organizations = fetch_qvain_admin_organizations_from_ldap(ldap_connection, user_id)
    if len(organizations) == 0:
        raise Exception("No admin organizations found for the specified id: %s" % user_id)
    user = {'id': user_id, 'admin_organizations': organizations}
    print(json.dumps(user, indent=4))
    ldap_connection.unbind()
except Exception as e:
    print(json.dumps({ "error": str(e) }, indent=4))
