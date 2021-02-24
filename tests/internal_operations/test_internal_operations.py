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
import sys
import shutil
import json
from pathlib import Path
from datetime import datetime

class TestInternalOperations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("=== tests/internal_operations")

    def setUp(self):

        print("(initializing)")

        self.config = json.load(open(os.environ.get('SSO_CONFIG')))
        self.services = json.load(open("%s/static/services.json" % os.environ.get('SSO_ROOT')))
        self.errors = json.load(open("%s/static/errors.json" % os.environ.get('SSO_ROOT')))
        self.success = False

    def tearDown(self):

        if self.success:

            print("(done)")

    def test_internal_operations(self):
        """
        Overview:

        This module tests all functionality of the SSO not relating to integration with
        Fairdata services or integration with the AAI proxy.
        """

        # --------------------------------------------------------------------------------

        print("--- Testing internal operations")

        print("Retrieve Swagger documentation")
        response = requests.get("%s/" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Swagger UI</title>", output)

        print("Retrieve test page")
        response = requests.get("%s/test" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertIn("<title>Fairdata SSO Test Page</title>", output)

        print("Retrieve robots.txt")
        response = requests.get("%s/robots.txt" % self.config["SSO_API"], verify=False)
        self.assertEqual(response.status_code, 200)
        output = response.content.decode(sys.stdout.encoding)
        self.assertEqual("User-agent: * Disallow: /", output)

        # --------------------------------------------------------------------------------
        # If all tests passed, record success, in which case tearDown will be done

        self.success = True

        # --------------------------------------------------------------------------------
        # TODO: consider which tests may be missing...
