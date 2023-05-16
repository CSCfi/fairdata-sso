import os
import json
from common import *

try:
    user_id = os.environ['LDAP_USER']
    ldap_connection = initialize_ldap_connection()
    print(json.dumps(fetch_user_details_from_ldap(ldap_connection, user_id), indent=4))
    ldap_connection.unbind()
except Exception as e:
    print(json.dumps({ "error": str(e) }, indent=4))
