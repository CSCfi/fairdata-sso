# --------------------------------------------------------------------------------
# Note regarding sequence of tests: this test case contains only a single test
# method, which utilizes the test projects, user accounts, and project data
# initialized during setup, such that the sequential actions in the single
# test method create side effects which subsequent actions and assertions may
# depend on. The state of the test accounts and data must be taken into account
# whenever adding tests at any particular point in that execution sequence.
# --------------------------------------------------------------------------------

import requests
import urllib
import subprocess
import unittest
import time
import os
import re
import sys
import shutil
import json
import base64
import jwt
from pathlib import Path
from datetime import datetime

class TestServiceIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("=== tests/service_integration")

    def setUp(self):

        print("(initializing)")

        self.config = json.load(open(os.environ.get('SSO_CONFIG')))
        self.services = json.load(open("%s/static/services.json" % os.environ.get('SSO_ROOT')))
        self.errors = json.load(open("%s/static/errors.json" % os.environ.get('SSO_ROOT')))
        self.saml = json.load(open(os.environ.get('SSO_SAML_CONFIG')))
        self.domain = self.config['DOMAIN']
        self.prefix = re.sub(r'[^a-zA-Z0-9]', '_', self.domain)
        self.key = self.saml['sp']['privateKey']
        self.success = False

    def tearDown(self):

        if self.success:

            print("(done)")

    def test_service_integration(self):

        """
        Overview:

        This module tests all functionality of the SSO relating to integration between the
        Fairdata services and the SSO and between the SSO and the Fairdata AAI proxy.
        """

        # --------------------------------------------------------------------------------

        print("--- Testing service integration")

        # /saml_metadata

        print ("Verify correct response from /saml_metadata")
        response = requests.get("%s/saml_metadata/" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertTrue('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"' in output)

        # /login

        for service_key in sorted(self.services.keys()):

            service = self.services[service_key]
            service_short_name = service.get('short_name')

            for language in [ 'en', 'fi', 'sv' ]:

                print ("Request login from %s service (language=%s)" % (service['short_name'], language))

                response = requests.get("%s/login?service=%s&redirect_url=%s&errors=csc_account_locked&language=%s" % (self.config["SSO_API"], service_key, urllib.parse.quote(self.config["SSO_API"]), language), verify=False)
                self.assertEqual(response.status_code, 200)
                output = response.content.decode(sys.stdout.encoding)
                self.assertIn("<title>Fairdata SSO Login</title>", output)

                print ("- verify error alert")

                if (language == 'fi'):
                    self.assertIn("CSC-tunnuksesi on lukittu.", output)
                elif (language == 'sv'):
                    self.assertIn("Ditt CSC-användarkonto är låst.", output)
                else:
                    self.assertIn("The CSC user account is locked.", output)

                print ("- verify guidance heading and text")

                if (language == 'fi'):
                    self.assertIn("%s-" % service_short_name, output)
                    self.assertIn("sisäänkirjautumisvaatimukset", output)
                elif (language == 'sv'):
                    self.assertIn("Inloggningskrav för %s:" % service_short_name, output)
                else:
                    self.assertIn("Login requirements for %s:" % service_short_name, output)

                self.assertIn(service['guidance_text'][language], output)

                print ("- verify guidance links")

                for guidance_link in service['guidance_links'][language]:
                    self.assertIn("<li><a href=\"%s\" target=\"_blank\">%s</a></li>" % (guidance_link['href'], guidance_link['text']), output)

                allowed_idps = service['allowed_identity_providers']
                available_idps = self.config.get('IDENTITY_PROVIDERS', ['CSCID', 'HAKA', 'VIRTU'])

                idps = []
                for idp in allowed_idps:
                    if idp in available_idps:
                        idps.append(idp)

                print ("- verify supported authentication options present")

                for idp in idps:
                    print ("     %s should be present" % idp)
                    self.assertIn("<a href=\"/auth?service=%s&redirect_url=%s&idp=%s&language=" % (service_key, urllib.parse.quote(self.config["SSO_API"]), idp), output)
                    if (language == 'fi'):
                        self.assertIn("<img src=\"%s.png\" alt=\"Kirjaudu sisään %slla\" />" % (idp, idp), output)
                    elif (language == 'sv'):
                        self.assertIn("<img src=\"%s.png\" alt=\"Logga in med %s\" />" % (idp, idp), output)
                    else:
                        self.assertIn("<img src=\"%s.png\" alt=\"Login using %s\" />" % (idp, idp), output)

                print ("- verify unsupported authentication options not present")

                for idp in ['CSCID', 'HAKA', 'VIRTU']:
                    if (idp not in idps):
                        print ("     %s should not be present" % idp)
                        if (language == 'fi'):
                            self.assertNotIn("<img src=\"%s.png\" alt=\"Kirjaudu sisään %slla\" />" % (idp, idp), output)
                        elif (language == 'sv'):
                            self.assertNotIn("<img src=\"%s.png\" alt=\"Logga in med %s\" />" % (idp, idp), output)
                        else:
                            self.assertNotIn("<img src=\"%s.png\" alt=\"Login using %s\" />" % (idp, idp), output)

        # /logout

        for service_key in sorted(self.services.keys()):

            service = self.services[service_key]
            service_short_name = service.get('short_name')

            for language in [ 'en', 'fi', 'sv' ]:

                print ("Request logout from %s service (language=%s)" % (service['short_name'], language))

                response = requests.get("%s/logout?service=%s&redirect_url=%s&language=%s" % (self.config["SSO_API"], service_key, urllib.parse.quote(self.config["SSO_API"]), language), verify=False)
                self.assertEqual(response.status_code, 200)
                output = response.content.decode(sys.stdout.encoding)
                self.assertIn("<title>Fairdata SSO Logout</title>", output)

                print ("- verify redirection URL")

                self.assertIn("<input type=\"hidden\" name=\"redirect_url\" value=\"%s\" />" % self.config["SSO_API"], output)

                print ("- verify guidance heading and text")

                if (language == 'fi'):
                    self.assertIn("Jatkamalla kirjaudut ulos <strong>kaikista</strong> Fairdata-palveluista, et vain %s-" % service_short_name, output)
                    self.assertIn("Kirjaudu ulos", output)
                elif (language == 'sv'):
                    self.assertIn("Detta avslutar den aktiva sessionen för <strong>ALL</strong> Fairdata Services, inte bara för %s" % service_short_name, output)
                    self.assertIn("Logga ut", output)
                else:
                    self.assertIn("This will end the active session for <strong>ALL</strong> Fairdata Services, not only for %s" % service_short_name, output)
                    self.assertIn("Logout", output)

        # /auth

        print ("Authenticate via proxy for IDA using CSCID for account fd_test_ida_user")
        response = requests.get("%s/auth?service=IDA&redirect_url=%s&idp=CSCID&language=en" % (self.config["SSO_API"], urllib.parse.quote(self.config["SSO_API"])), verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        print ("Verify fairdata service is specified in redirect to proxy")
        location = response.headers.get('Location')
        self.assertIsNotNone(location)
        self.assertTrue('/idp/profile/SAML2/Redirect/SSO' in location)
        self.assertTrue('service=IDA' in location)

        # /acs
        # /terminate

        print ("Initiate mock session for IDA using CSCID for account fd_test_ida_user")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_test_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)

        print ("Validate current session details stored in cookies")
        session_data_string = session.cookies.get("%s_fd_sso_session" % self.prefix)
        self.assertIsNotNone(session_data_string)
        session_data = jwt.decode(session_data_string, self.key, algorithms=['HS256'])
        #print(json.dumps(session_data, indent=4, sort_keys=True))
        qvain_admin_orgs = "_%s_" % '_'.join(sorted(session_data['services']['QVAIN']['admin_organizations']))
        self.assertEqual(qvain_admin_orgs, '_aalto.fi_csc.fi_')
        services = session_data.get('services')
        if services:
            services = "_%s_" % '_'.join(sorted(services.keys()))
        self.assertEqual(services, '_AVAA_ETSIN_IDA_QVAIN_')
        projects = session_data.get('projects')
        if projects:
            projects = "_%s_" % '_'.join(sorted(projects.keys()))
        self.assertEqual(projects, '_fd_test_ida_project_fd_test_multiproject_a_fd_test_multiproject_b_')
        projects = session_data['services']['IDA']['projects']
        projects = "_%s_" % '_'.join(projects)
        self.assertEqual(projects, '_fd_test_ida_project_fd_test_multiproject_a_fd_test_multiproject_b_')
        authenticated_user = session_data.get('authenticated_user')
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.get('id'), 'fd_test_ida_user')
        self.assertEqual(authenticated_user.get('identity_provider'), 'CSCID')
        self.assertEqual(session_data.get('initiating_service'), 'IDA')
        fairdata_user = session_data.get('fairdata_user')
        self.assertIsNotNone(fairdata_user)
        self.assertEqual(fairdata_user.get('id'), 'fd_test_ida_user')
        self.assertFalse(fairdata_user.get('locked', False))

        print ("Attempt to terminate current session without specifying redirect URL")
        data = {"service": "IDA"}
        response = session.post("%s/terminate" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("Required parameter 'redirect_url' missing", output)

        print ("Attempt to terminate current session without specifying service")
        data = {"redirect_url": self.config["SSO_API"]}
        response = session.post("%s/terminate" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("Required parameter 'service' missing", output)

        print ("Terminate current session")
        data = {"redirect_url": self.config["SSO_API"], "service": "IDA"}
        response = session.post("%s/terminate" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))

        print ("Attempt to initiate mock session for IDA using HAKA for account fd_non_ida_user")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "HAKA",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_non_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Login</title>", output)
        self.assertIn("You are not a member of any project in IDA or you have not yet accepted the IDA terms of use in MyCSC.", output)

        print ("Initiate mock session for Etsin using HAKA for account fd_non_ida_user")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "ETSIN",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "HAKA",
            "fd_sso_language": "sv",
            "mockauthfile": "%s/tests/mock/fd_non_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)

        print ("Validate current session details stored in cookies")
        output = response.content.decode(sys.stdout.encoding)
        session_data_string = session.cookies.get("%s_fd_sso_session" % self.prefix)
        self.assertIsNotNone(session_data_string)
        session_data = jwt.decode(session_data_string, self.key, algorithms=['HS256'])
        services = session_data.get('services')
        if services:
            services = "_%s_" % '_'.join(sorted(services.keys()))
        self.assertEqual(services, '_AVAA_ETSIN_QVAIN_')
        authenticated_user = session_data.get('authenticated_user')
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.get('id'), 'fd_non_ida_user')
        self.assertEqual(authenticated_user.get('identity_provider'), 'HAKA')
        self.assertEqual(session_data.get('initiating_service'), 'ETSIN')
        fairdata_user = session_data.get('fairdata_user')
        self.assertIsNotNone(fairdata_user)
        self.assertEqual(fairdata_user.get('id'), 'fd_non_ida_user')
        self.assertFalse(fairdata_user.get('locked', False))

        print ("Terminate current session")
        data = {"redirect_url": self.config["SSO_API"], "service": "ETSIN"}
        response = session.post("%s/terminate" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))

        print ("Initiate mock session for IDA using CSCID for account fd_logindisabled_user")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_logindisabled_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)

        print ("Validate current session details stored in cookies")
        session_data_string = session.cookies.get("%s_fd_sso_session" % self.prefix)
        self.assertIsNotNone(session_data_string)
        session_data = jwt.decode(session_data_string, self.key, algorithms=['HS256'])
        services = session_data.get('services')
        if services:
            services = "_%s_" % '_'.join(sorted(services.keys()))
        self.assertEqual(services, '_AVAA_ETSIN_IDA_QVAIN_')
        authenticated_user = session_data.get('authenticated_user')
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.get('id'), 'fd_logindisabled_user')
        self.assertEqual(authenticated_user.get('identity_provider'), 'CSCID')
        self.assertEqual(session_data.get('initiating_service'), 'IDA')
        fairdata_user = session_data.get('fairdata_user')
        self.assertIsNotNone(fairdata_user)
        self.assertEqual(fairdata_user.get('id'), 'fd_logindisabled_user')
        self.assertFalse(fairdata_user.get('locked', False))

        print ("Terminate current session")
        data = {"redirect_url": self.config["SSO_API"], "service": "IDA"}
        response = session.post("%s/terminate" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))

        print ("Attempt to initiate mock session for IDA using HAKA for account fd_non_csc_user")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "HAKA",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_non_csc_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Login</title>", output)
        self.assertIn("Logging into this service requires a CSC account.", output)
        self.assertIn("You are not a member of any project in IDA or you have not yet accepted the IDA terms of use in MyCSC.", output)

        print ("Attempt to initiate mock session for Etsin using HAKA for account fd_non_csc_user")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "ETSIN",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "HAKA",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_non_csc_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Login</title>", output)
        self.assertIn("Logging into this service requires a CSC account.", output)
        self.assertIn("To be able to download data from Etsin that require you to log in, you must have a CSC user account.", output)

        print ("Initiate mock session for PAS using CSCID for account fd_pas_user_propose")
        session = requests.Session()
        data = {
            "fd_sso_initiating_service": "PAS",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_pas_user_propose.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)

        print ("Validate current session details stored in cookies")
        session_data_string = session.cookies.get("%s_fd_sso_session" % self.prefix)
        self.assertIsNotNone(session_data_string)
        session_data = jwt.decode(session_data_string, self.key, algorithms=['HS256'])
        services = session_data.get('services')
        if services:
            services = "_%s_" % '_'.join(sorted(services.keys()))
        self.assertEqual(services, '_AVAA_ETSIN_PAS_QVAIN_')
        authenticated_user = session_data.get('authenticated_user')
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.get('id'), 'fd_pas_user_propose')
        self.assertEqual(authenticated_user.get('identity_provider'), 'CSCID')
        self.assertEqual(session_data.get('initiating_service'), 'PAS')
        fairdata_user = session_data.get('fairdata_user')
        self.assertIsNotNone(fairdata_user)
        self.assertEqual(fairdata_user.get('id'), 'fd_pas_user_propose')
        self.assertFalse(fairdata_user.get('locked', False))

        print ("Terminate current session using /sls endpoint")
        data = {"redirect_url": self.config["SSO_API"]}
        response = session.post("%s/sls/" % self.config["SSO_API"], data=data, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(session.cookies.get("%s_fd_sso_idp" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_redirect_url" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_initiating_service" % self.prefix))
        self.assertIsNone(session.cookies.get("%s_fd_sso_session" % self.prefix))

        print ("Attempt to retrieve user status for non-existent user")
        data = {
            "id": "no_such_user",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/user_status" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 404)

        print ("Retrieve user status for known user without Qvain admin privileges")
        data = {
            "id": "fd_test_multiproject_user_ab",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/user_status" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 200)
        user = response.json()
        projects = user.get('projects', [])
        organizations = user.get('qvain_admin_organizations', [])
        self.assertTrue(len(projects) == 2)
        self.assertTrue('fd_test_multiproject_a' in projects)
        self.assertTrue('fd_test_multiproject_b' in projects)
        self.assertTrue(len(organizations) == 0)

        print ("Retrieve user status for known user with Qvain admin privileges")
        data = {
            "id": "fd_test_qvain_user",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/user_status" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 200)
        user = response.json()
        projects = user.get('projects', [])
        organizations = user.get('qvain_admin_organizations', [])
        self.assertTrue(len(projects) == 1)
        self.assertTrue('fd_test_qvain_project' in projects)
        self.assertTrue(len(organizations) == 1)
        self.assertTrue('csc.fi' in organizations)

        print ("Attempt to retrieve project status for non-existent project")
        data = {
            "id": "no_such_project",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/project_status" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 404)

        print ("Retrieve project status for known project")
        data = {
            "id": "fd_test_multiproject_a",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/project_status" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 200)
        project = response.json()
        users = project.get('users', {})
        self.assertTrue(len(users) == 2)
        self.assertTrue('fd_test_multiproject_user_a' in users)
        self.assertTrue('fd_test_multiproject_user_ab' in users)

        print ("Attempt to retrieve preservation agreement privileges for non-existent user")
        data = {
            "id": "no_such_user",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/preservation_agreements" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 404)

        print ("Retrieve preservation agreement privileges for known user")
        data = {
            "id": "fd_pas_user_fetch",
            "token": self.config["TRUSTED_SERVICE_TOKEN"]
        }
        response = session.post("%s/preservation_agreements" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 200)

        # --------------------------------------------------------------------------------
        # If all tests passed, record success, in which case tearDown will be done

        self.success = True

        # --------------------------------------------------------------------------------
        # TODO: consider which tests may be missing...
