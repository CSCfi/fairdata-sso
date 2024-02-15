import os
import json
from dateutil import parser
from ldap3 import Server, ServerPool, Connection, ALL, FIRST


def initialize_ldap_connection():
    """
    Initialize an LDAP connection per the defined configuration
    """

    config = json.load(open("%s/config.json" % os.environ['SSO_ROOT']))
    
    ldap_hosts = config['LDAP_HOSTS']
    ldap_read_user = config['LDAP_READ_USER']
    ldap_read_password = config['LDAP_READ_PASSWORD']
    ldap_servers = []
    
    for ldap_server_url in ldap_hosts:
        ldap_servers.append(Server(ldap_server_url, use_ssl=True, get_info=ALL))
    
    ldap_server_pool = ServerPool(ldap_servers, FIRST, active=True, exhaust=True)
    ldap_connection = Connection(ldap_server_pool, ldap_read_user, ldap_read_password, auto_bind=True)

    if ldap_connection and ldap_connection.bound:
        return ldap_connection
    else:
        raise Exception("LDAP initialization failed: %s" % str(ldap_connection))


def normalize_timestamp_string(timestamp):
    """
    Creates an ISO UTC formated datetime string from a datetime value.
    """
    return timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')


def fetch_user_details_from_ldap(ldap_connection, user_id, full=True):

    ldap_search_base = "ou=idm,dc=csc,dc=fi"

    ldap_query = "(&(objectClass=person)(cn=%s))" % user_id

    ldap_connection.search(ldap_search_base, ldap_query, attributes=[
        'cn',
        'modifyTimestamp',
        'CSCUserName',
        'nsaccountlock',
        'memberOf',
        'sn',
        'givenName',
        'uid',
        'mail'
    ])

    count = len(ldap_connection.entries)

    if count < 1:
        raise Exception("No user found for the specified id: %s" % user_id)

    if count > 1:
        # Presumably this should never happen, but we will check for it anyway to be sure
        raise Exception("Multiple user accounts found with specified id: %s" % user_id)

    entry = ldap_connection.entries[0]

    user = {}
    user['name'] = "%s %s" % (str(entry.givenName), str(entry.sn))
    user['email'] = str(entry.mail)
    user['locked'] = (str(entry.nsaccountlock) == 'true')

    if full:

        user['modified'] = normalize_timestamp_string(parser.parse(str(entry.modifyTimestamp)))

        user_id = str(entry.CSCUserName)

        if user_id == '':
            user_id = str(entry.uid)

        if user_id == '':
            user_id = str(entry.cn)

        user['id'] = user_id

        projects = []

        try:
            groups = json.loads(str(entry.memberOf).replace("'", '"'))
        except:
            groups = []

        for group in groups:

            i = group.find(',')
            project = group[3:i]

            # If project is not 'csc' and not personal (internal/academic), add normalized project number / name

            if project != 'csc':

                ldap_query = "(&(objectClass=CSCProject)(!(CSCPrjScope=personal))(|(CSCPrjNum=%s)(cn=%s)))" % (project, project)
                ldap_connection.search(ldap_search_base, ldap_query, attributes=['CSCPrjNum'])
    
                if len(ldap_connection.entries) > 0:
                    entry = ldap_connection.entries[0]
                    try:
                        project = str(entry.CSCPrjNum)
                    except:
                        if project.startswith('project_'):
                            project = project[8:]
                    projects.append(project)
    
        user['projects'] = projects

        organizations = fetch_qvain_admin_organizations_from_ldap(ldap_connection, user_id)

        if len(organizations) > 0:
            user['qvain_admin_organizations'] = organizations

    return user


def fetch_qvain_admin_organizations_from_ldap(ldap_connection, user_id):

    organizations = []

    ldap_search_base = "ou=organizations,ou=idm,dc=csc,dc=fi"

    ldap_query = "(CSCOrgQvainMainUsers=cn=%s,*)" % user_id

    ldap_connection.search(ldap_search_base, ldap_query, attributes=['eduOrgHomePageURI'])

    for entry in ldap_connection.entries:

        dn = str(entry.eduOrgHomePageURI)
        
        fields = dn.split('.')
        
        total = len(fields)
        
        if total > 2:
            orgdomain = "%s.%s" % (fields[total-2], fields[total-1])
        else:
            orgdomain = fields[total-1]

        organizations.append(orgdomain)

    return organizations


def fetch_project_details_from_ldap(ldap_connection, project_id):

    ldap_search_base = "ou=idm,dc=csc,dc=fi"

    ldap_query = "(&(objectClass=CSCProject)(|(CSCPrjNum=%s)(cn=%s)))" % (project_id, project_id)

    ldap_connection.search(ldap_search_base, ldap_query, attributes=[
        'cn',
        'CSCPrjTitle',
        'CSCPrjScope',
        'CSCPrjState',
        'CSCPrjtype',
        'modifyTimestamp',
        'memberUid'
    ])

    count = len(ldap_connection.entries)

    if count < 1:
        raise Exception("No project found for the specified id: %s" % project_id)

    if count > 1:
        # Presumably this should never happen, but we will check for it anyway to be sure
        raise Exception("Multiple projects found with specified id: %s" % project_id)

    entry = ldap_connection.entries[0]

    project = {}
    project['id'] = str(entry.cn)
    project['title'] = str(entry.CSCPrjTitle)
    project['scope'] = str(entry.CSCPrjScope)
    project['state'] = str(entry.CSCPrjState)
    project['modified'] = normalize_timestamp_string(parser.parse(str(entry.modifyTimestamp)))

    project_types = []
    for project_type in entry.CSCPrjType:
        project_types.append(str(project_type))
    project['types'] = project_types

    project_users = {}
    for project_user in entry.memberUid:
        user_id = str(project_user)
        user_summary = fetch_user_details_from_ldap(ldap_connection, user_id, full=False)
        project_users[user_id] = user_summary
    project['users'] = project_users

    return project


def fetch_pas_agreements_from_ldap(ldap_connection, user_id):

    ldap_search_base = "ou=idm,dc=csc,dc=fi"

    ldap_query = "(&(objectClass=CSCDPSClass)(|(CSCDPSWatchDN=cn=%s,*)(CSCDPSApproveDN=cn=%s,*)(CSCDPSFetchDN=cn=%s,*)(CSCDPSSuggestDN=cn=%s,*)))" % (user_id, user_id, user_id, user_id)

    ldap_connection.search(ldap_search_base, ldap_query, attributes=['+', '*'])

    agreements = {}

    for entry in ldap_connection.entries:

        agreement_id = str(entry.CSCDPSUID)
        privileges = []

        try:
            attval = str(entry.CSCDPSWatchDN)
            if attval and "cn=%s," % user_id in attval:
                privileges.append('view')
        except:
            pass

        try:
            attval = str(entry.CSCDPSApproveDN)
            if attval and "cn=%s," % user_id in attval:
                privileges.append('approve')
        except:
            pass

        try:
            attval = str(entry.CSCDPSFetchDN)
            if attval and "cn=%s," % user_id in attval:
                privileges.append('fetch')
        except:
            pass

        try:
            attval = str(entry.CSCDPSSuggestDN)
            if attval and "cn=%s," % user_id in attval:
                privileges.append('propose')
        except:
            pass

        if len(privileges) > 0:
            agreements[agreement_id] = privileges

    return agreements
