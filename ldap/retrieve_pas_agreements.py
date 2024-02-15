import json
from common import *

try:
    user_id = os.environ['LDAP_USER']
    ldap_connection = initialize_ldap_connection()
    agreements = fetch_pas_agreements_from_ldap(ldap_connection, user_id)
    if len(agreements) == 0:
        raise Exception("No preservation agreements found for the specified id: %s" % user_id)
    user = {'id': user_id, 'agreements': agreements}
    print(json.dumps(user, indent=4))
    ldap_connection.unbind()
except Exception as e:
    print(json.dumps({ "error": str(e) }, indent=4))
