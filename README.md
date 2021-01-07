[![pipeline status](https://gitlab.ci.csc.fi/fairdata/fairdata-sso-dev/badges/test/pipeline.svg)](https://gitlab.ci.csc.fi/fairdata/fairdata-sso-dev/-/commits/test)

This is the implementation of the Fairdata SSO service.

See the swagger documentation for
detailed information regarding the service and API, available via the API endpoint `/swagger`
after successful deployment, or `swagger/swagger.html` locally.

# Configuration

Standard practice is for the repository to be cloned into the directory `/var/fairdata-sso`.

Python3 must be installed, and a virtual environment initialized by running the script

    utils/initialize-venv

A configuration file `config.json` must be created, defining the essential configuration
variables for the service. See the example file templates/config.json

A SAML settings file `saml.json` must be created, defining the essential SAML2 settings for the
service. See the example file templates/saml.json

After all of the above is done, setup as a service is done once by running the script

    utils/initialize-service

which also will run the `initialize-venv` script.

The service can be managed using the `systemctl` command. E.g.:

    systemctl status fairdata-sso
    systemctl start fairdata-sso
    systemctl stop fairdata-sso
    systemctl restart fairdata-sso

