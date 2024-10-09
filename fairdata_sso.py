import os
import sys
import logging
import json
import time
import uuid
import re
import urllib.parse
import requests
import socket
import subprocess
import jwt
import socket
import html
import validators
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, make_response
from flask_seasurf import SeaSurf
from flask_talisman import Talisman
from onelogin.saml2.auth import OneLogin_Saml2_Auth

config = json.load(open(os.environ.get('SSO_CONFIG')))
error_messages = json.load(open("%s/static/errors.json" % os.environ.get('SSO_ROOT')))
saml = json.load(open(os.environ.get('SSO_SAML_CONFIG')))

services = json.load(open("%s/static/services.json" % os.environ.get('SSO_ROOT')))
AVAILABLE_SERVICES = services.keys()
AVAILABLE_IDENTITY_PROVIDERS = config.get('IDENTITY_PROVIDERS', [ 'CSCID', 'HAKA', 'VIRTU' ])
AVAILABLE_LANGUAGES = [ 'en', 'fi', 'sv' ]

domain = config['DOMAIN']
prefix = re.sub(r'[^a-zA-Z0-9]', '_', domain)
debug = config.get('DEBUG')
not_production = config.get('ENVIRONMENT') != 'PRODUCTION'

class localFlask(Flask):
    def process_response(self, response):
        # Every response will be processed here first
        # Most security headers will be handled by flask-talisman and flask-seasurf
        # We fix additional server headers to not reveal implementation details
        response.headers['server'] = "Fairdata SSO for %s" % domain
        response.headers['host'] = "sso.%s" % domain
        return(response)

app = Flask(__name__, static_folder='static', static_url_path='')

app.secret_key = saml['sp']['privateKey']

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

app.config['CSRF_COOKIE_HTTPONLY'] = True
app.config['CSRF_COOKIE_SECURE'] = True
app.config['CSRF_COOKIE_SAMESITE'] = 'Strict'

app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

csrf = SeaSurf(app)

csp = {
    'default-src': [
        "'self'",
        "'unsafe-inline'",
        'metrics.fairdata.fi',
        'metrics.fd-dev.csc.fi',
        'metrics.fd-test.csc.fi'
    ],
    'img-src': '* data:'
}

csp_swagger = {
    'default-src': [
        "'self'",
        "'unsafe-inline'",
        'cdnjs.cloudflare.com',
        'fonts.googleapis.com',
        'fonts.gstatic.com'
    ],
    'img-src': '* data:'
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    frame_options='DENY',
    feature_policy={'geolocation': '\'none\''}
)

loglevel = logging.INFO

if debug:
    loglevel = logging.DEBUG

logging.basicConfig(
    level=loglevel,
    filename="%s/%s.log" % (config['LOG_ROOT'], domain),
    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
    datefmt="%Y-%m-%dT%H:%M:%SZ")

logging.Formatter.converter = time.gmtime

log = app.logger

if debug:
    log.debug("DEBUG LOGGING ON")
    log.debug("DOMAIN: %s" % domain)
    log.debug("PREFIX: %s" % prefix)
    log.debug("ENVIRONMENT: %s" % config.get('ENVIRONMENT'))
    log.debug("IDENTITY_PROVIDERS: %s" % json.dumps(AVAILABLE_IDENTITY_PROVIDERS))

#--------------------------------------------------------------------------------

# Remove authentication options if not enabled for environment, e.g. in DEMO environment
for service in AVAILABLE_SERVICES:
    allowed_identity_providers = services[service]['allowed_identity_providers']
    idps = []
    for identity_provider in allowed_identity_providers:
        if identity_provider in AVAILABLE_IDENTITY_PROVIDERS:
            idps.append(identity_provider)
    services[service]['allowed_identity_providers'] = idps

log.debug("SERVICES: %s" % json.dumps(services))

#--------------------------------------------------------------------------------

SAML_ATTRIBUTES = {
    'first_name':    'urn:oid:2.5.4.42',
    'last_name':     'urn:oid:2.5.4.4',
    'email':         'urn:oid:0.9.2342.19200300.100.1.3',
    'haka_id':       'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',
    'home_org_id':   'urn:oid:1.3.6.1.4.1.25178.1.2.9',
    'home_org_name': 'urn:oid:1.3.6.1.4.1.16161.4.0.88',
    'csc_username':  'urn:oid:1.3.6.1.4.1.16161.4.0.53',
    'idm_groups':    'urn:oid:1.3.6.1.4.1.8057.2.80.26'
}

# IdP URLs per the specified 'ENVIRONMENT' defined in config.json:

IDP = {
    'PRODUCTION': {
        'CSCID': 'https://fd-auth.fairdata.fi/loginCSC',
        'HAKA':  'https://fd-auth.fairdata.fi/loginHaka',
        'VIRTU': 'https://fd-auth.fairdata.fi/loginVirtu'
    },
    'DEMO': {
        'CSCID': 'https://fd-auth-demo.fairdata.fi/loginCSC',
        'HAKA':  'https://fd-auth-demo.fairdata.fi/loginHaka',
        'VIRTU': 'https://fd-auth-demo.fairdata.fi/loginVirtu'
    },
    'REWORK': {
        'CSCID': 'https://fd-auth-dev.csc.fi/LoginCSC',
        'HAKA':  'https://fd-auth-dev.csc.fi/LoginHakaTest',
        'VIRTU': 'https://fd-auth-dev.csc.fi/LoginVirtuTest'
    },
    'DEV': {
        'CSCID': 'https://fd-auth-dev.csc.fi/LoginCSC',
        'HAKA':  'https://fd-auth-dev.csc.fi/LoginHakaTest',
        'VIRTU': 'https://fd-auth-dev.csc.fi/LoginVirtuTest'
    },
    'STABLE': {
        'CSCID': 'https://fd-auth-dev.csc.fi/LoginCSC',
        'HAKA':  'https://fd-auth-dev.csc.fi/LoginHakaTest',
        'VIRTU': 'https://fd-auth-dev.csc.fi/LoginVirtuTest'
    },
    'STAGING': {
        'CSCID': 'https://fd-auth-dev.csc.fi/LoginCSC',
        'HAKA':  'https://fd-auth-dev.csc.fi/LoginHakaTest',
        'VIRTU': 'https://fd-auth-dev.csc.fi/LoginVirtuTest'
    },
    'TEST': {
        'CSCID': 'https://fd-auth-dev.csc.fi/LoginCSC',
        'HAKA':  'https://fd-auth-dev.csc.fi/LoginHakaTest',
        'VIRTU': 'https://fd-auth-dev.csc.fi/LoginVirtuTest'
    }
}

log.debug("INITIALIZED")

#--------------------------------------------------------------------------------


def generate_token():
    """
    Creates a unique token
    """

    return uuid.uuid4().hex


def generate_session_id():
    """
    Creates a dated, unique, URL-safe string for use as a session id
    """

    date = datetime.utcnow().strftime('%Y-%m-%d-%H%M%S')
    token = generate_token()

    return "%s%s" % (date, token)


def generate_timestamp_string(now=None, delta=None):
    """
    Creates an ISO UTC formated datetime string. If a datetime is not provided, uses
    the current time. If a time delta is provided, offsets the datetime accordingly.
    """

    if not now:
        now = datetime.utcnow()
    if delta:
        now = now + timedelta(0, delta)

    return now.strftime('%Y-%m-%dT%H:%M:%SZ')


def initiate_session(service, idp, saml):
    """
    Initiates and returns a sso session object based on the provided SAML authentication
    response details, aggregating additional user details as needed, and distilling all
    relevant user details into a simple, normalized object, excluding a session id
    or initialized and expiration timestamps, which are defined only after the session is
    validated per the requirements of a specified service.
    """

    session = dict()
    session['initiating_service'] = service

    authenticated_user = dict()
    authenticated_user['id'] = get_user_id(saml)
    authenticated_user['identity_provider'] = idp
    authenticated_user_email = get_user_email(saml)
    if authenticated_user_email:
        authenticated_user['email'] = authenticated_user_email
    firstname = get_user_firstname(saml)
    if firstname:
        authenticated_user['firstname'] = firstname
    lastname = get_user_lastname(saml)
    if lastname:
        authenticated_user['lastname'] = lastname

    organization = dict()
    organization['id'] = get_user_home_organization_id(saml)
    organization['name'] = get_user_home_organization_name(saml)
    authenticated_user['organization'] = organization
    session['authenticated_user'] = authenticated_user

    fairdata_user_id = get_user_csc_name(saml)

    if fairdata_user_id:
        fairdata_user = dict()
        fairdata_user['id'] = fairdata_user_id
        fairdata_user['locked'] = has_locked_CSC_account(saml)
        session['fairdata_user'] = fairdata_user

    groups = get_user_groups(saml) or []

    projects = get_projects(groups)
    services = get_services(projects)

    qvain_admin_organizations = get_qvain_admin_organizations(groups)

    if qvain_admin_organizations:
        if services.get('QVAIN'):
            services['QVAIN']['admin_organizations'] = qvain_admin_organizations
        else:
            services['QVAIN'] = { "admin_organizations": qvain_admin_organizations }

    pas_agreements = fetch_pas_agreements_from_ldap(fairdata_user_id).get('agreements')

    if pas_agreements:
        if services.get('PAS'):
            services['PAS']['agreements'] = pas_agreements
        else:
            services['PAS'] = { "agreements": pas_agreements }

    session['projects'] = projects
    session['services'] = services

    log.info("initiate_session: %s" % json.dumps(session))

    return session


def validate_session(service, session):
    """
    Validate the specified session per the requirements of the specified service. If any
    issues are identified, record them in the session object in an array value stored in
    the root field 'errors'.
    """

    errors = list()

    service_settings = services.get(service)
    active_user_services = session.get('services')
    fairdata_user = session.get('fairdata_user')

    log.debug("validate_session: service_settings=%s" % json.dumps(service_settings))
    log.debug("validate_session: active_user_services=%s" % json.dumps(active_user_services))
    log.debug("validate_session: fairdata_user=%s" % json.dumps(fairdata_user))

    if (service_settings.get('cscid_required') == True and not fairdata_user):
        errors.append("no_csc_account") # Not linked to a CSC account

    if (service_settings.get('cscid_locked_ok') == False and fairdata_user and fairdata_user.get('locked') == True):
        errors.append("csc_account_locked") # CSC account is locked"

    if (service == 'IDA' and (not active_user_services or not active_user_services.get('IDA'))):
        errors.append("no_ida_projects") # The authenticated account has no active IDA projects

    # If the user does not have rights to use the requested service and there are no other more
    # specific error messages recorded, add a default error message

    if (len(errors) == 0 and (not active_user_services or active_user_services.get(service) == None)):
        if service == 'PAS':
            errors.append("no_pas_service_rights") 
        else:
            errors.append("no_service_rights") # Service agnostic fallback error message

    if (len(errors) > 0):
        session['errors'] = errors

    log.info("validate_session: session=%s" % json.dumps(session))

    return session


def get_saml_auth(flask_request):
    """
    Used by saml library.

    Arguments:
        flask_request [] -- []

    Returns:
        [] -- []
    """

    idp = flask_request.values.get('idp')
    log.debug("1) Inside get_saml_auth, this is idp=%s" % idp)

    if idp:
        env = config.get('ENVIRONMENT', 'TEST')
        log.debug("1) Inside get_saml_auth, this is env=%s" % env)
        saml['security']['requestedAuthnContext'] = [IDP[env][idp]]
        saml['security']['requestedAuthnContextComparison'] = 'exact'
        saml['security']['failOnAuthnContextMismatch'] = True

    log.debug("get_saml_auth: SAML AUTHENTICATION SETTINGS: %s" % saml)

    return OneLogin_Saml2_Auth(prepare_flask_request_for_saml(flask_request), saml)


def init_saml_auth(saml_prepared_flask_request, idp):
    """
    Used by saml library.

    Arguments:
        saml_prepared_flask_request [] -- []
        idp -- IDP to be used

    Returns:
        [] -- []
    """

    # It would appear that this idp variable is always "None"
    # idp = saml_prepared_flask_request.get('idp')

    log.debug("3) Inside init_saml_auth, this is idp=%s" % idp)

    if idp:
        env = config.get('ENVIRONMENT', 'TEST')
        log.debug("3) Inside init_saml_auth, this is env=%s" % env)
        saml['security']['requestedAuthnContext'] = [IDP[env][idp]]
        saml['security']['requestedAuthnContextComparison'] = 'exact'
        saml['security']['failOnAuthnContextMismatch'] = True

    return OneLogin_Saml2_Auth(saml_prepared_flask_request, saml)


def prepare_flask_request_for_saml(request):
    """
    Used by saml library.

    Arguments:
        request [dict] -- request

    Returns:
        [dict] -- configs for saml
    """

    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields

    url_data = urlparse(request.url)

    # If in local development environment this will redirect the saml login right.

    if request.host == 'localhost':
        request.host = '30.30.30.30'

    flask_request = {
        'https': 'on',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'idp': request.values.get('idp')
    }

    log.debug("prepare_flask_request_for_saml: flask_request=%s" % json.dumps(flask_request))

    return flask_request


def not_found(field, saml):
    """
    Log if field not found in session samlUserdata.

    Arguments:
        field [string] -- Name of the field not found.
        saml [dict] -- SAML authentication response details
    """

    log.warning('User seems to be authenticated but {0} not in session object.'.format(field))

    log.debug('not_found: Saml userdata:\n{0}'.format(saml.get('samlUserdata', None)))


def is_authenticated(saml):
    """
    Test if the user is authenticated.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [boolean] -- True/False
    """

    return True if 'samlUserdata' in saml and len(saml.get('samlUserdata', None)) > 0 else False


def has_locked_CSC_account(saml):
    """
    Test if the user is an authenticated CSC user but the CSC account is locked.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [boolean] -- True/False
    """

    # NOTE: currently, the authentication proxy will reject authentication when a user's account
    # is locked so this function will never be true, but we will leave this functionality as-is
    # in case the proxy behavior ever changes in the future and we need to handle such cases.

    return True if is_authenticated_CSC_user(saml) and saml.get('nsAccountLock', None) == 'true' else False


def is_authenticated_CSC_user(saml):
    """
    Test if the authenticated user account equates to a CSC account.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [boolean] -- True/False
    """

    username = SAML_ATTRIBUTES['csc_username']

    return True if 'samlUserdata' in saml and len(saml.get('samlUserdata', None)) > 0 and username in saml.get('samlUserdata', None) else False


def get_user_csc_name(saml):
    """
    Get user csc name from saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The users CSC username.
    """

    if not is_authenticated(saml) or not is_authenticated_CSC_user(saml) or 'samlUserdata' not in saml:
        return None

    csc_name = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('csc_username', None), False)

    return csc_name[0] if csc_name else not_found('csc_name', saml)


def get_user_haka_identifier(saml):
    """
    Get user HAKA identifier from saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The users HAKA identifier.
    """

    if not is_authenticated(saml) or 'samlUserdata' not in saml:
        return None

    haka_id = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('haka_id', None), False)

    return haka_id[0] if haka_id else not_found('haka_id', saml)


def get_user_id(saml):
    """
    Get user identifier. If csc_username is found return that, else try to find Haka identifier.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- User identifer.
    """

    csc_name = get_user_csc_name(saml)

    if csc_name:
        return csc_name

    haka_id = get_user_haka_identifier(saml)

    if haka_id:
        return haka_id

    return None


def get_user_email(saml):
    """
    Get user email from saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The users email.
    """

    if not is_authenticated(saml) or not is_authenticated_CSC_user(saml) or 'samlUserdata' not in saml:
        return None

    csc_email = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('email', None), False)

    return csc_email[0] if csc_email else not_found('csc_email', saml)


def get_user_lastname(saml):
    """
    Get user last name from saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The users last name
    """

    if not is_authenticated(saml) or 'samlUserdata' not in saml:
        return None

    lastname = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('last_name', None), False)

    return lastname[0] if lastname else not_found('lastname', saml)


def get_user_firstname(saml):
    """
    Get user first name from saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The users first name
    """

    if not is_authenticated(saml) or 'samlUserdata' not in saml:
        return None

    first_name = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('first_name', None), False)

    return first_name[0] if first_name else not_found('first_name', saml)


def get_user_groups(saml):
    """
    Get the Groups from CSC IdM for the user.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [list] -- List of all the groups.
    """

    if not is_authenticated(saml) or 'samlUserdata' not in saml:
        return None

    groups = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('idm_groups', None), False)

    return [group for group in groups] if groups else not_found('groups', saml)


def get_user_home_organization_id(saml):
    """
    Get the home organization id from the saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The id of the users home organization.
    """

    if not is_authenticated(saml) or 'samlUserdata' not in saml:
        return None

    home_organization = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('home_org_id', None), False)

    return home_organization[0] if home_organization else not_found('home_organization', saml)


def get_user_home_organization_name(saml):
    """
    Get the home organization name from the saml userdata.

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [string] -- The name of the users home organization.
    """

    if not is_authenticated(saml) or 'samlUserdata' not in saml:
        return None

    home_organization_id = saml.get('samlUserdata', {}).get(SAML_ATTRIBUTES.get('home_org_name', None), False)

    return home_organization_id[0] if home_organization_id else not_found('home_organization_id', saml)


def get_projects(groups):
    """
    Get all projects to which the user belongs, and for each project, which services the user can access for that project.

    Arguments:
        groups [list] -- list of groups returned in SAML response

    Returns:
        [dict] -- The projects dict
    """

    projects = dict()

    log.debug("get_projects: groups=%s" % json.dumps(groups))

    for group in groups:

        # Check for colon in group string, skip group
        try:
            i = group.index(':')
        except:
            i = -1

        # We only care about groups with a colon, which separates profile name from project name
        if i > 0:

            project_services = dict()

            # Extract profile name preceeding colon
            profile_name = group[:i]

            # If special PAS admin group name, define virtual PAS project
            if profile_name == 'FPAS-MGMT':
                if group == 'FPAS-MGMT:Admin':
                    project_name = '2001465'
                else:
                    continue
            # Else, extract project name following colon
            else:
                project_name = group[i+1:]

            log.debug("get_projects: profile_name=%s project_name=%s" % (profile_name, project_name))

            # Iterate over services in service configuration
            for (service_name, service_config) in services.items():

                log.debug("get_projects: service_name=%s" % service_name)

                supported_profiles = service_config.get('cscid_supported_profiles')

                log.debug("get_projects: supported_profiles=%s" % json.dumps(supported_profiles))

                # if profile is in set of allowed profiles, add service to array of services for project
                if supported_profiles and profile_name in supported_profiles:
                    log.debug("get_projects: supported_profile=%s" % profile_name)
                    project_services[service_name] = True

            log.debug("get_projects: project_services=%s" % json.dumps(project_services))

            # If project services dict is not empty, record in projects dict
            if len(project_services) > 0:

                project_services_keys = [*project_services]
                log.debug("get_projects: project_services_keys=%s" % json.dumps(project_services_keys))

                recorded_project = projects.get(project_name, dict())
                recorded_services_keys = recorded_project.get('services', [])

                recorded_project['services'] = list(sorted(set(project_services_keys + recorded_services_keys)))

                # Record new/updated project in set of user projects
                projects[project_name] = recorded_project

    log.debug("get_projects: projects=%s" % json.dumps(projects))

    return projects


def get_services(projects):
    """
    Invert the specified projects dict, creating a services dict encoding which services the user has
    access to, and for each, which projects the service can access.

    Arguments:
        projects [dict] -- The projects dict

    Returns:
        [dict] -- The services dict
    """

    services = dict()

    for project_name, project_dict in projects.items():
        project_services = project_dict.get('services', list())
        for service_name in project_services:
            service = services.get(service_name, dict())
            projects = service.get('projects', list())
            projects.append(project_name)
            service['projects'] = projects
            services[service_name] = service

    # Authenticated users are allowed to use Etsin, Qvain, Metax, and AVAA (there are no special profiles for those)

    for service_key in [ 'ETSIN', 'QVAIN', 'METAX', 'AVAA' ]:
        if (not services.get(service_key)):
            services[service_key] = dict()

    log.debug("get_services: services=%s" % json.dumps(services))

    return services


def get_qvain_admin_organizations(groups):
    """
    Get all organizations for which the user has Qvain admin priveleges, if any

    Arguments:
        saml [dict] -- SAML authentication response details

    Returns:
        [list] -- The list of zero or more organizations
    """

    organizations = list()

    log.debug("get_qvain_admin_organizations: groups=%s" % json.dumps(groups))

    for group in groups:

        log.debug("get_qvain_admin_organizations: group=%s" % json.dumps(group))

        # Check for colon in group string, skip group
        try:
            i = group.index(':')
        except:
            i = -1

        # We only care about groups with a colon, which separates profile name from project or organization name
        if i > 0:

            # Extract profile name preceeding colon
            profile_name = group[:i]

            # If special Qvain Admin profile name, extract organization from group
            if profile_name == 'QVAINADMIN':
                organization = group[i+1:]

                log.debug("get_qvain_admin_organizations: profile_name=%s organization=%s" % (profile_name, organization))

                # Add organization to list of organizations
                organizations.append(organization)

    log.debug("get_qvain_admin_organizations: organizations=%s" % json.dumps(organizations))

    return organizations


def get_language(request):
    try:
        language = request.accept_languages.best_match(AVAILABLE_LANGUAGES)
        # Normalize the language code
        language = language[:2]
        return language if language else 'en'
    except:
        return 'en'


def fdwe_get_environment():
    domain = config['DOMAIN']
    if (domain == 'fairdata.fi'):
        environment = "PRODUCTION"
    elif (domain == 'demo.fairdata.fi'):
        environment = "DEMO"
    elif (domain == 'fd-stable.csc.fi'):
        environment = "STABLE"
    elif (domain == 'fd-staging.csc.fi'):
        environment = "STAGING"
    elif (domain == 'fd-test.csc.fi'):
        environment = "TEST"
    elif (domain == 'fd-rework.csc.fi'):
        environment = "REWORK"
    else:
        environment = "DEV"
    log.debug("fdwe_get_environment: environment=%s" % environment)
    return environment


def fdwe_record_event(scope):
    try:
        if 'FDWE_MATOMO_API' in config:
            log.debug("fdwe_record_event: scope=%s" % scope)
            session = requests.Session()
            data = {
               "idsite": config['FDWE_SITE_ID'],
               "rec": 1,
               "action_name": "%s / SSO / %s" % (fdwe_get_environment(), scope),
               "rand": generate_token(),
               "apiv": 1
            }
            log.debug("fdwe_record_event: title=%s" % data['action_name'])
            response = session.post("%s" % config['FDWE_MATOMO_API'], data=data, verify=False)
            if response.status_code != 200:
                log.error("Error: Failed to record web event: %s  Response: %d %s" % (data['action_name'], response.status_code, response.content))
    except Exception as e:
        log.error("Exception: %s" % str(e))


def fetch_user_details_from_ldap(user_id):
    try:
        env = os.environ.copy()
        env["LDAP_USER"] = user_id
        cmd = "%s/ldap/retrieve-user-details 2>&1" % os.environ['SSO_ROOT']
        output = subprocess.check_output(cmd, shell=True, env=env, stderr=subprocess.STDOUT).decode(sys.stdout.encoding).strip()
        return json.loads(output)
    except Exception as e:
        error = "LDAP query failed: %s" % str(e)
        log.error("fetch_user_details_from_ldap: %s" % error)
        return { 'error': error }


def fetch_project_details_from_ldap(project_id):
    try:
        env = os.environ.copy()
        env["LDAP_PROJECT"] = project_id
        cmd = "%s/ldap/retrieve-project-details 2>&1" % os.environ['SSO_ROOT']
        output = subprocess.check_output(cmd, shell=True, env=env, stderr=subprocess.STDOUT).decode(sys.stdout.encoding).strip()
        return json.loads(output)
    except Exception as e:
        error = "LDAP query failed: %s" % str(e)
        log.error("fetch_project_details_from_ldap: %s" % error)
        return { 'error': error }


def fetch_qvain_admin_organizations_from_ldap(user_id):
    try:
        env = os.environ.copy()
        env["LDAP_USER"] = user_id
        cmd = "%s/ldap/retrieve-qvain-admin-organizations 2>&1" % os.environ['SSO_ROOT']
        output = subprocess.check_output(cmd, shell=True, env=env, stderr=subprocess.STDOUT).decode(sys.stdout.encoding).strip()
        return json.loads(output)
    except Exception as e:
        error = "LDAP query failed: %s" % str(e)
        log.error("fetch_qvain_admin_organizations_from_ldap: %s" % error)
        return { 'error': error }


def fetch_pas_agreements_from_ldap(user_id):
    try:
        env = os.environ.copy()
        env["LDAP_USER"] = user_id
        cmd = "%s/ldap/retrieve-pas-agreements 2>&1" % os.environ['SSO_ROOT']
        output = subprocess.check_output(cmd, shell=True, env=env, stderr=subprocess.STDOUT).decode(sys.stdout.encoding).strip()
        return json.loads(output)
    except Exception as e:
        error = "LDAP query failed: %s" % str(e)
        log.error("fetch_pas_agreements_from_ldap: %s" % error)
        return { 'error': error }


@talisman(content_security_policy=csp_swagger)
@app.route('/', methods=['GET'])
@app.route('/swagger', methods=['GET'])
def swagger():
    """
    Returns the online Swagger API documentation page
    """

    pathname = "%s/swagger/swagger.html" % os.environ.get('SSO_ROOT')
    content = open(pathname).read()

    response = make_response(content)
    response.mimetype = "text/html"
    return response


@app.route('/test', methods=['GET'])
def test():
    """
    Returns a web page for manually testing SSO functionality
    """

    fd_sso_session = request.cookies.get("%s_fd_sso_session" % prefix)

    if fd_sso_session:
        try:
            log.debug("index: fd_sso_session (encrypted): %s" % fd_sso_session)
            fd_sso_session = jwt.decode(fd_sso_session, app.secret_key, algorithms=['HS256'])
            log.debug("index: fd_sso_session (decrypted): %s" % fd_sso_session)
            fd_sso_session = json.dumps(fd_sso_session, indent=4, sort_keys=True)
        except:
            fd_sso_session = 'Error: decoding of session object failed'

    fd_sso_session_id = request.cookies.get("%s_fd_sso_session_id" % prefix)

    if fd_sso_session_id:
        fd_sso_session_id = html.escape(fd_sso_session_id)

    context = {
        "sso_api": config.get('SSO_API', "https://sso.%s" % domain),
        "prefix": prefix,
        "fd_sso_session_id": fd_sso_session_id,
        "fd_sso_session": fd_sso_session,
        "fdwe_url": config.get('FDWE_URL')
    }

    return render_template('test.html', **context)


@app.route('/login', methods=['GET'])
def login():
    """
    Log in to the Fairdata SSO.
    """

    service = request.values.get('service')

    if not service:
        response = make_response("Required parameter 'service' missing", 400)
        response.mimetype = "text/plain"
        return response

    service = html.escape(service)

    if not service in AVAILABLE_SERVICES:
        response = make_response("Invalid value for parameter \'service\': %s" % service, 400)
        response.mimetype = "text/plain"
        return response

    redirect_url = request.values.get('redirect_url')

    if not redirect_url:
        response = make_response("Required parameter 'redirect_url' missing", 400)
        response.mimetype = "text/plain"
        return response

    if not validators.url(redirect_url):
        response = make_response("Invalid value for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    parsed_url = urllib.parse.urlparse(redirect_url)
    url_domain = '.'.join(parsed_url.hostname.split('.')[1:])

    if not url_domain == domain:
        response = make_response("Invalid domain for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    idps = services[service]["allowed_identity_providers"]

    errors_data = []
    error_codes = request.args.get('errors')

    if error_codes:
        try:
            for error in error_codes.split(','):
                errors_data.append(error_messages.get(error, {
                    "en": { "text": error, "link": "", "href": "" },
                    "fi": { "text": error, "link": "", "href": "" },
                    "sv": { "text": error, "link": "", "href": "" }
                }))
        except:
            pass

    language = request.values.get('language')

    if language:
        language = html.escape(language)
        if not language in AVAILABLE_LANGUAGES:
            response = make_response("Invalid value for parameter \'language\': %s" % language, 400)
            response.mimetype = "text/plain"
            return response

    if not language:
        language = get_language(request)

    context = {
        "service": service,
        "service_object": services[service],
        "service_short_name": services[service]["short_name"],
        "allowed_idps": services[service]["allowed_identity_providers"],
        "redirect_url": urllib.parse.quote(redirect_url),
        "errors": errors_data,
        "error_codes": error_codes,
        "language": language,
        "fdwe_url": config.get('FDWE_URL')
    }

    log.debug("login: context: %s" % json.dumps(context))

    return render_template('login.html', **context)


@app.route('/logout', methods=['GET'])
def logout():
    """
    Log out of the Fairdata SSO.
    """

    service = request.values.get('service')

    if not service:
        response = make_response("Required parameter 'service' missing", 400)
        response.mimetype = "text/plain"
        return response

    service = html.escape(service)

    if not service in AVAILABLE_SERVICES:
        response = make_response("Invalid value for parameter \'service\': %s" % service, 400)
        response.mimetype = "text/plain"
        return response

    redirect_url = request.values.get('redirect_url')

    if not redirect_url:
        response = make_response("Required parameter 'redirect_url' missing", 400)
        response.mimetype = "text/plain"
        return response

    if not validators.url(redirect_url):
        response = make_response("Invalid value for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    parsed_url = urllib.parse.urlparse(redirect_url)
    url_domain = '.'.join(parsed_url.hostname.split('.')[1:])

    if not url_domain == domain:
        response = make_response("Invalid domain for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    language = request.values.get('language')

    if language:
        language = html.escape(language)
        if not language in AVAILABLE_LANGUAGES:
            response = make_response("Invalid value for parameter \'language\': %s" % language, 400)
            response.mimetype = "text/plain"
            return response

    if not language:
        language = get_language(request)

    context = {
        "service": service,
        "service_object": services[service],
        "service_short_name": services[service]["short_name"],
        "redirect_url": redirect_url,
        "sso_api": config['SSO_API'],
        "language": language,
        "fdwe_url": config.get('FDWE_URL')
    }

    return render_template('logout.html', **context)


@app.route('/auth', methods=['GET'])
def authentication():
    """
    Initiate authentication via a selected identity provider.
    """

    service = request.values.get('service')

    if not service:
        response = make_response("Required parameter 'service' missing", 400)
        response.mimetype = "text/plain"
        return response

    service = html.escape(service)

    if not service in AVAILABLE_SERVICES:
        response = make_response("Invalid value for parameter \'service\': %s" % service, 400)
        response.mimetype = "text/plain"
        return response

    redirect_url = request.values.get('redirect_url')

    if not redirect_url:
        response = make_response("Required parameter 'redirect_url' missing", 400)
        response.mimetype = "text/plain"
        return response

    if not validators.url(redirect_url):
        response = make_response("Invalid value for parameter \'redirect_url\': %s" % html.escape(redirect_url), 400)
        response.mimetype = "text/plain"
        return response

    parsed_url = urllib.parse.urlparse(redirect_url)
    url_domain = '.'.join(parsed_url.hostname.split('.')[1:])

    if not url_domain == domain:
        response = make_response("Invalid domain for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    idp = request.values.get('idp')

    if not idp:
        response = make_response("Required parameter 'idp' missing", 400)
        response.mimetype = "text/plain"
        return response

    idp = html.escape(idp)

    if not idp in AVAILABLE_IDENTITY_PROVIDERS:
        response = make_response("Invalid value for parameter \'idp\': %s" % idp, 400)
        response.mimetype = "text/plain"
        return response

    log.debug("authentication: IDP: %s" % idp)

    language = request.values.get('language')

    if not language:
        response = make_response("Required parameter 'language' missing", 400)
        response.mimetype = "text/plain"
        return response

    auth = get_saml_auth(request)

    log.debug("authentication: AUTH: %s" % repr(auth.get_settings().get_sp_metadata()))

    saml_redirect_url = urllib.parse.quote(request.args.get('relay', request.base_url))

    log.debug("authentication: SAML REDIRECT URL: %s" % urllib.parse.unquote(saml_redirect_url))

    # Store the requesting service and redirect URL in cookies so we have them after the SAML response

    auth_init = {
        "initiating_service": service,
        "idp": idp,
        "redirect_url": redirect_url,
        "language": language
    }

    auth_init_encrypted = jwt.encode(auth_init, app.secret_key, algorithm='HS256')

    auth_redirect_url = "%s&service=%s" % (auth.login(saml_redirect_url, force_authn=True), service)

    log.debug("authentication: AUTH REDIRECT URL: %s" % urllib.parse.unquote(auth_redirect_url))

    response = make_response(redirect(auth_redirect_url))
    response.set_cookie("%s_fd_sso_authenticate" % prefix, value=auth_init_encrypted, domain=domain, max_age=config['MAX_AGE'], secure=True, httponly=True, samesite='Strict')

    return response


@app.route('/saml_metadata/', methods=['GET'])
def saml_metadata():
    """
    Return the public SAML XML metadata for the SSO service.
    """

    auth = get_saml_auth(request)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        response = make_response(metadata, 200)
        response.headers['Content-Type'] = 'text/xml'
    else:
        response = make_response(', '.join(errors), 500)
        response.headers['Content-Type'] = 'text/plain'

    return response


@csrf.exempt
@app.route('/acs/', methods=['POST'])
def saml_attribute_consumer_service():
    """
    The endpoint used by the SAML library on auth.login call from the AAI proxy after successful authentication.
    """

    log.debug("saml_attribute_consumer_service")

    language = 'en'

    authentication_errors = []

    if ((not_production or debug) and request.values.get('testing') == 'true'):

        log.debug("In testing, demo, or debug")

        service = request.values.get("fd_sso_initiating_service")

        if not service:
            response = make_response("Required parameter 'fd_sso_initiating_service' missing", 400)
            response.mimetype = "text/plain"
            return response

        service = html.escape(service)

        if not service in AVAILABLE_SERVICES:
            response = make_response("Invalid value for parameter \'fd_sso_initiating_service\': %s" % service, 400)
            response.mimetype = "text/plain"
            return response

        redirect_url = request.values.get("fd_sso_redirect_url")
    
        if not redirect_url:
            response = make_response("Required parameter 'fd_sso_redirect_url' missing", 400)
            response.mimetype = "text/plain"
            return response

        if not validators.url(redirect_url):
            response = make_response("Invalid value for parameter \'fd_sso_redirect_url\': %s" % redirect_url, 400)
            response.mimetype = "text/plain"
            return response

        parsed_url = urllib.parse.urlparse(redirect_url)
        url_domain = '.'.join(parsed_url.hostname.split('.')[1:])

        if not url_domain == domain:
            response = make_response("Invalid domain for parameter \'redirect_url\': %s" % redirect_url, 400)
            response.mimetype = "text/plain"
            return response

        idp = request.values.get("fd_sso_idp")

        if not idp:
            response = make_response("Required parameter 'fd_sso_idp' missing", 400)
            response.mimetype = "text/plain"
            return response

        idp = html.escape(idp)

        if not idp in AVAILABLE_IDENTITY_PROVIDERS:
            response = make_response("Invalid value for parameter \'fd_sso_idp\': %s" % idp, 400)
            response.mimetype = "text/plain"
            return response

        language = request.values.get("fd_sso_language")

        if not language:
            response = make_response("Required parameter 'fd_sso_language' missing", 400)
            response.mimetype = "text/plain"
            return response

        # mockauthfile corresponds to the full pathname of a mock SAML result dict,
        # simulating the dict constructed below based on the results of the call to
        # auth.process_response() below, encoded as a JSON object file; tests may
        # simulate multiple scenarios by providing the pathname of different mock
        # authentication result files

        mockauthfile = request.values.get('mockauthfile')

        if not mockauthfile:
            response = make_response("Required parameter 'mockauthfile' missing", 400)
            response.mimetype = "text/plain"
            return response

        # Use the URL validator to check for well formed pathname by constructing bogus URL
        file_url = "https://sso.%s%s" % (domain, mockauthfile)

        if not validators.url(file_url):
            response = make_response("Invalid value for parameter \'mockauthfile\': %s" % mockauthfile, 400)
            response.mimetype = "text/plain"
            return response

        try:
            saml = json.load(open(mockauthfile))
        except:
            response = make_response("Failed to load the specified \'mockauthfile\': %s" % mockauthfile, 400)
            response.mimetype = "text/plain"
            return response

    else:

        log.debug("NOT in dev, testing, demo, or debug -> 'production' type environment...")

        auth_init = request.cookies.get("%s_fd_sso_authenticate" % prefix)

        if not auth_init:
            response = make_response("Required cookie '%s_fd_sso_authenticate' missing or has expired" % prefix, 400)
            response.mimetype = "text/plain"
            return response

        try:
            auth_init = jwt.decode(auth_init, app.secret_key, algorithms=['HS256'])
        except:
            response = make_response("Failed to decode cookie '%s_fd_sso_authenticate'" % prefix, 400)
            response.mimetype = "text/plain"
            return response

        service = auth_init.get('initiating_service')
    
        if not service:
            response = make_response("Required value 'service' missing" % prefix, 400)
            response.mimetype = "text/plain"
            return response

        redirect_url = auth_init.get('redirect_url')
    
        if not redirect_url:
            response = make_response("Required value 'redirect_url' missing" % prefix, 400)
            response.mimetype = "text/plain"
            return response

        parsed_url = urllib.parse.urlparse(redirect_url)
        url_domain = '.'.join(parsed_url.hostname.split('.')[1:])

        if not url_domain == domain:
            response = make_response("Invalid domain for value 'redirect_url': %s" % (prefix, redirect_url), 400)
            response.mimetype = "text/plain"
            return response

        idp = auth_init.get('idp')
    
        if not idp:
            response = make_response("Required value 'idp' missing" % prefix, 400)
            response.mimetype = "text/plain"
            return response

        log.debug("2) Inside saml_attribute_consumer_service(), idp=%s" % idp)

        language = auth_init.get('language')
    
        if not language:
            response = make_response("Required value 'language' missing" % prefix, 400)
            response.mimetype = "text/plain"
            return response

        log.debug("2) Inside saml_attribute_consumer_service(), before prepare_flask_request_for_saml... request=%s" % request)

        req = prepare_flask_request_for_saml(request)

        log.debug("2) Inside saml_attribute_consumer_service(), will send req to init_saml_auth... req=%s" % req)

        auth = init_saml_auth(req, idp)

        log.debug("SAML RESPONSE: %s" % auth.get_last_response_xml())

        auth.process_response()

        authentication_errors = auth.get_errors()

        if len(authentication_errors) > 0:
            saml_last_error_reason = auth.get_last_error_reason()
            if saml_last_error_reason:
                authentication_errors.append(saml_last_error_reason)

        saml = dict()
        saml['isAuthenticated'] = auth.is_authenticated()
        saml['errors'] = authentication_errors
        saml['samlUserdata'] = auth.get_attributes()

    log.debug("acs: SAML AUTHENTICATION RESULT: %s" % json.dumps(saml))

    if not saml['isAuthenticated'] or len(authentication_errors) > 0:
        errorList = ",".join(authentication_errors)
        url = "%s/login?service=%s&redirect_url=%s&idp=%s&errors=%s&language=%s" % (config['SSO_API'], service, urllib.parse.quote(redirect_url), idp, urllib.parse.quote(errorList), language)
        response = make_response(redirect(url))
        response.set_cookie("%s_fd_sso_session_id" % prefix, value='', domain=domain, max_age=0)
        response.set_cookie("%s_fd_sso_authenticate" % prefix, value='', domain=domain, max_age=0)
        response.set_cookie("%s_fd_sso_session" % prefix, value='', domain=domain, max_age=0)
        return response
    
    # Generate session object with all essential user details and service privileges

    session = initiate_session(service, idp, saml)

    # Validate the generated session per the specified service
    # If any issues are identified, redirect back to login with the issues reported

    session = validate_session(service, session)

    # Report errors, if any, returning to login page

    errors = session.get('errors')

    if (errors):
        error_codes = ','.join(errors)
        log.warning("acs: errors: %s" % error_codes)
        url = "%s/login?service=%s&redirect_url=%s&idp=%s&language=%s&errors=%s" % (config['SSO_API'], service, urllib.parse.quote(redirect_url), idp, language, error_codes)
        response = make_response(redirect(url))
        response.set_cookie("%s_fd_sso_session_id" % prefix, value='', domain=domain, max_age=0)
        response.set_cookie("%s_fd_sso_authenticate" % prefix, value='', domain=domain, max_age=0)
        response.set_cookie("%s_fd_sso_session" % prefix, value='', domain=domain, max_age=0)
        return response

    # Record session and session cookies

    if session.get('fairdata_user') != None:
        username = session['fairdata_user']['id']
    else:
        username = session['authenticated_user']['id']

    now = datetime.utcnow()

    session['id'] = generate_session_id()
    session['initiated'] = generate_timestamp_string(now)
    session['expiration'] = generate_timestamp_string(now, config['MAX_AGE'])
    session['redirect_url'] = redirect_url
    session['language'] = language

    log.debug("acs: services: %s" % services)

    if debug:
        session['user_groups'] = get_user_groups(saml) or []

    log.debug("acs: session now: %d" % now.timestamp())
    log.debug("acs: session max: %d" % config['MAX_AGE'])
    exp = int(now.timestamp() + config['MAX_AGE'])
    log.debug("acs: session exp: %d" % exp)

    session['exp'] = exp
    session_encrypted = jwt.encode(session, app.secret_key, algorithm='HS256')

    log.debug("acs: session (encrypted): %s" % session_encrypted)

    response = make_response(redirect(redirect_url))

    response.set_cookie("%s_fd_sso_authenticate" % prefix, value='', domain=domain, max_age=0)
    response.set_cookie("%s_fd_sso_session_id" % prefix, value=session['id'], domain=domain, max_age=config['MAX_AGE'], secure=True, httponly=True, samesite='Strict')
    response.set_cookie("%s_fd_sso_session" % prefix, value=session_encrypted, domain=domain, max_age=config['MAX_AGE'], secure=True, httponly=True, samesite='Strict')

    log.debug("acs: session=%s" % json.dumps(session))

    # Anonymize the logged session data in production so there are no GDPR issues

    if (session.get('authenticated_user')):
        session['authenticated_user']['id'] = None
        session['authenticated_user']['name'] = None
        session['authenticated_user']['email'] = None

    if (session.get('fairdata_user')):
        session['fairdata_user']['id'] = None

    session['projects'] = dict()

    for service_key in session['services'].keys():
        session['services'][service_key]['projects'] = []

    log.debug("acs: session=%s" % json.dumps(session))

    fdwe_record_event("LOGIN / %s / SUCCESS" % service)

    return response


@csrf.exempt
@app.route('/sls/', methods=['POST'])
def saml_single_logout_service():
    """
    The endpoint used by the SAML library on auth.logout call from the AAI proxy.

    In practice, this endpoint will never be used, but as it is required for the AAI integration,
    we'll ensure it does the right thing in a reasonable manner. It will terminate the session,
    flushing all session cookies, and will redirect the user back to the service via which the
    session was initiated. If there is no active session, it will redirect to fairdata.fi.
    """

    redirect_url = "https://fairdata.fi"

    response = make_response(redirect(redirect_url))
    response.set_cookie("%s_fd_sso_session_id" % prefix, value='', domain=domain, max_age=0)
    response.set_cookie("%s_fd_sso_session" % prefix, value='', domain=domain, max_age=0)

    log.debug("sls: session=%s" % request.cookies.get("%s_fd_sso_session_id" % prefix))

    fdwe_record_event("LOGOUT / AAI / SUCCESS")

    return response


@csrf.exempt
@app.route('/terminate', methods=['POST'])
def terminate():
    """
    Terminate the current session, if any.
    """

    service = request.values.get('service')

    if not service:
        response = make_response("Required parameter 'service' missing", 400)
        response.mimetype = "text/plain"
        return response

    redirect_url = request.values.get('redirect_url')

    if not redirect_url:
        response = make_response("Required parameter 'redirect_url' missing", 400)
        response.mimetype = "text/plain"
        return response

    if not validators.url(redirect_url):
        response = make_response("Invalid value for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    parsed_url = urllib.parse.urlparse(redirect_url)
    url_domain = '.'.join(parsed_url.hostname.split('.')[1:])

    if not url_domain == domain:
        response = make_response("Invalid domain for parameter \'redirect_url\': %s" % redirect_url, 400)
        response.mimetype = "text/plain"
        return response

    response = make_response(redirect(redirect_url))

    response.set_cookie("%s_fd_sso_session_id" % prefix, value='', domain=domain, max_age=0)
    response.set_cookie("%s_fd_sso_session" % prefix, value='', domain=domain, max_age=0)

    log.info("terminate: session=%s" % request.cookies.get("%s_fd_sso_session_id" % prefix))
    
    fdwe_record_event("LOGOUT / %s / SUCCESS" % service)

    return response


@csrf.exempt
@app.route('/user_status', methods=['POST'])
def user_status():
    """
    Return a summary of the current status of the specified user, including project membership and whether the account is disabled
    """

    user_id = request.values.get('id')

    if not user_id:
        response = make_response("Required parameter 'id' missing", 400)
        response.mimetype = "text/plain"
        return response

    # sanitize input to protect against injections that could carry over into LDAP queries
    user_id = re.sub(r'[^\w\@\.\-]', '', user_id)

    token = request.values.get('token')

    if not token:
        response = make_response("Required parameter 'token' missing", 400)
        response.mimetype = "text/plain"
        return response

    if token != config.get('TRUSTED_SERVICE_TOKEN'):
        response = make_response("Invalid token", 401)
        response.mimetype = "text/plain"
        return response

    user = fetch_user_details_from_ldap(user_id)

    error = user.get('error')

    if error:
        if error.startswith('No user found for the specified id:'):
            response = make_response(error, 404)
            response.mimetype = "text/plain"
            return response
        else:
            response = make_response(error, 500)
            response.mimetype = "text/plain"
            return response

    return user


@csrf.exempt
@app.route('/project_status', methods=['POST'])
def project_status():
    """
    Return a summary of the current status of the specified project, including project membership
    """

    project_id = request.values.get('id')

    if not project_id:
        response = make_response("Required parameter 'id' missing", 400)
        response.mimetype = "text/plain"
        return response

    # sanitize input to protect against injections that could carry over into LDAP queries
    project_id = re.sub(r'[^\w\@\.\-]', '', project_id)

    token = request.values.get('token')

    if not token:
        response = make_response("Required parameter 'token' missing", 400)
        response.mimetype = "text/plain"
        return response

    if token != config.get('TRUSTED_SERVICE_TOKEN'):
        response = make_response("Invalid token", 401)
        response.mimetype = "text/plain"
        return response

    project = fetch_project_details_from_ldap(project_id)

    error = project.get('error')

    if error:
        if error.startswith('No project found for the specified id:'):
            response = make_response(error, 404)
            response.mimetype = "text/plain"
            return response
        else:
            response = make_response(error, 500)
            response.mimetype = "text/plain"
            return response

    return project


@csrf.exempt
@app.route('/preservation_agreements', methods=['POST'])
def preservation_agreements():
    """
    Return a summary of user-specific preservation agreement privileges of the specified user, if any
    """

    user_id = request.values.get('id')

    if not user_id:
        response = make_response("Required parameter 'id' missing", 400)
        response.mimetype = "text/plain"
        return response

    # sanitize input to protect against injections that could carry over into LDAP queries
    user_id = re.sub(r'[^\w\@\.\-]', '', user_id)

    token = request.values.get('token')

    if not token:
        response = make_response("Required parameter 'token' missing", 400)
        response.mimetype = "text/plain"
        return response

    if token != config.get('TRUSTED_SERVICE_TOKEN'):
        response = make_response("Invalid token", 401)
        response.mimetype = "text/plain"
        return response

    user = fetch_pas_agreements_from_ldap(user_id)

    error = user.get('error')

    if error:
        if error.startswith('No preservation agreements found for the specified id:'):
            response = make_response(error, 404)
            response.mimetype = "text/plain"
            return response
        else:
            response = make_response(error, 500)
            response.mimetype = "text/plain"
            return response

    return user


@app.before_request
def checkForArbitraryHostHeader():
    headers = dict(request.headers)
    host = headers.get('Host')
    if host:
        host, sep, port = host.partition(':')
        hostname = socket.gethostname()
        log.debug("checkForArbitraryHostHeader: Host=%s hostname=%s" % (host, hostname))
        if not debug and not host in [ 'localhost', '127.0.0.1', '0.0.0.0', 'sso.fairdata.fi', 'fdsso1.csc.fi', 'fdsso2.csc.fi', hostname ]:
            return make_response('Connection Closed Without Response', 444, {})


if __name__ == '__main__':
    app.run(host='0.0.0.0')

