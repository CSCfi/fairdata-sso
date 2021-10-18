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

#TODO:
#
#For each normal endpoint, execute REST request and verify correct security headers are defined
#For each CSRF exempt endpoint, execute REST request and verify correct security headers are defined
#For swagger endpoint, execute REST request and verify correct security headers are defined

class TestSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("=== tests/security")

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

    def test_security(self):

        """
        Overview:

        This module tests all functionality of the SSO relating to security.
        """

        # --------------------------------------------------------------------------------

        print("--- Testing security")

        print ("Verify correct security headers for /robots.txt")
        response = requests.get("%s/robots.txt" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("User-agent: * Disallow: /", output)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/plain; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertTrue('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /saml_metadata/")
        response = requests.get("%s/saml_metadata/" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/xml')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertTrue('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /swagger")
        response = requests.get("%s/" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Swagger UI</title>", output)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' cdnjs.cloudflare.com fonts.googleapis.com fonts.gstatic.com 'unsafe-inline'; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' cdnjs.cloudflare.com fonts.googleapis.com fonts.gstatic.com 'unsafe-inline'; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertTrue('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /test")
        response = requests.get("%s/test" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Test Page</title>", output)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertTrue('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /login")
        response = requests.get("%s/login?service=IDA&redirect_url=%s&errors=csc_account_locked&language=en" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Login</title>", output)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertTrue('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /logout")
        response = requests.get("%s/logout?service=IDA&redirect_url=%s&language=en" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Logout</title>", output)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertTrue('_csrf_token=' in headers.get('Set-Cookie'))

        session = requests.Session()

        print ("Verify correct security headers for /acs")
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_test_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertFalse('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /terminate")
        data = {"redirect_url": self.config["SSO_API"], "service": "IDA"}
        response = session.post("%s/terminate" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertFalse('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify correct security headers for /sls")
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_test_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        response = session.post("%s/sls/" % self.config["SSO_API"], verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        headers = dict(response.headers)
        self.assertEqual(headers.get('Content-Type'), 'text/html; charset=utf-8')
        self.assertEqual(headers.get('Feature-Policy'), "geolocation 'none'")
        self.assertEqual(headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(headers.get('Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('X-Content-Security-Policy'), "default-src 'self' metrics.fairdata.fi metrics.fd-test.csc.fi; img-src * data:")
        self.assertEqual(headers.get('Strict-Transport-Security'), 'max-age=31556926; includeSubDomains')
        self.assertEqual(headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertFalse('_csrf_token=' in headers.get('Set-Cookie'))

        print ("Verify rejection of arbitrary Host header values")
        if not self.config['DEBUG']:
            headers = { 'Host': 'bogus.com' }
            response = requests.get("%s/robots.txt" % self.config["SSO_API"], headers=headers, verify=False)
            self.assertEqual(response.status_code, 444)

        # TODO: add tests for injections

        print ("Attempt login with injection into service name parameter")
        response = requests.get("%s/login?service=javascript%%3aalert(document.domain)%%2f%%2ffoo&redirect_url=https://foo.bar.com" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'service': javascript:alert(document.domain)//foo", output)

        print ("Attempt login with injection into redirect URL parameter")
        response = requests.get("%s/login?service=IDA&redirect_url=javascript%%3aalert(document.domain)%%2f%%2ffoo" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'redirect_url': javascript:alert(document.domain)//foo", output)

        print ("Attempt login with invalid domain for redirect URL parameter")
        response = requests.get("%s/login?service=IDA&redirect_url=https://foo.com" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid domain for parameter 'redirect_url': https://foo.com", output)

        print ("Attempt login with injection into language parameter")
        response = requests.get("%s/login?service=IDA&redirect_url=%s&language=javascript%%3aalert(document.domain)%%2f%%2ffoo" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'language': javascript:alert(document.domain)//foo", output)

        print ("Attempt logout with injection into service name parameter")
        response = requests.get("%s/logout?service=javascript%%3aalert(document.domain)%%2f%%2ffoo&redirect_url=%s" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'service': javascript:alert(document.domain)//foo", output)

        print ("Attempt logout with injection into redirect URL parameter")
        response = requests.get("%s/logout?service=IDA&redirect_url=javascript%%3aalert(document.domain)%%2f%%2ffoo" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'redirect_url': javascript:alert(document.domain)//foo", output)

        print ("Attempt logout with invalid domain for redirect URL parameter")
        response = requests.get("%s/logout?service=IDA&redirect_url=https://foo.com" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid domain for parameter 'redirect_url': https://foo.com", output)

        print ("Attempt logout with injection into language parameter")
        response = requests.get("%s/logout?service=IDA&redirect_url=%s&language=javascript%%3aalert(document.domain)%%2f%%2ffoo" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'language': javascript:alert(document.domain)//foo", output)

        print ("Attempt authentication initiation with injection into service name parameter")
        response = requests.get("%s/auth?service=javascript%%3aalert(document.domain)%%2f%%2ffoo&redirect_url=%s" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'service': javascript:alert(document.domain)//foo", output)

        print ("Attempt authentication initiation with injection into redirect URL parameter")
        response = requests.get("%s/auth?service=IDA&redirect_url=javascript%%3aalert(document.domain)%%2f%%2ffoo" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'redirect_url': javascript:alert(document.domain)//foo", output)

        print ("Attempt authentication initiation with invalid domain for redirect URL parameter")
        response = requests.get("%s/auth?service=IDA&redirect_url=https://foo.com" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid domain for parameter 'redirect_url': https://foo.com", output)

        print ("Attempt authentication initiation with injection into IDP parameter")
        response = requests.get("%s/auth?service=IDA&redirect_url=%s&idp=javascript%%3aalert(document.domain)%%2f%%2ffoo" % (self.config["SSO_API"], self.config["SSO_API"]), verify=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'idp': javascript:alert(document.domain)//foo", output)

        print ("Attempt mock proxy response with injection into service name parameter")
        data = {
            "fd_sso_initiating_service": "javascript:alert(document.domain)//foo",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_test_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'fd_sso_initiating_service': javascript:alert(document.domain)//foo", output)

        print ("Attempt mock proxy response with injection into redirect URL parameter")
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": "javascript:alert(document.domain)//foo",
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_test_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'fd_sso_redirect_url': javascript:alert(document.domain)//foo", output)

        print ("Attempt mock proxy response with injection into IDP parameter")
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "javascript:alert(document.domain)//foo",
            "fd_sso_language": "en",
            "mockauthfile": "%s/tests/mock/fd_test_ida_user.json" % os.environ.get('SSO_ROOT'),
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'fd_sso_idp': javascript:alert(document.domain)//foo", output)

        print ("Attempt mock proxy response with injection into mockauthfile parameter")
        data = {
            "fd_sso_initiating_service": "IDA",
            "fd_sso_redirect_url": self.config["SSO_API"],
            "fd_sso_idp": "CSCID",
            "fd_sso_language": "en",
            "mockauthfile": "javascript:alert(document.domain)//foo", 
            "testing": "true"
        }
        response = session.post("%s/acs/" % self.config["SSO_API"], data=data, verify=False, allow_redirects=False)
        self.assertEqual(response.status_code, 400)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("Invalid value for parameter 'mockauthfile': javascript:alert(document.domain)//foo", output)

        # --------------------------------------------------------------------------------
        # If all tests passed, record success, in which case tearDown will be done

        self.success = True

        # --------------------------------------------------------------------------------
        # TODO: consider which tests may be missing...
