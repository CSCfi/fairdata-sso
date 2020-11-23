
This is the implementation of the Fairdata SSO service.

See the swagger documentation for
detailed information regarding the service and API, available via the API endpoint `/swagger`
after successful deployment, or `swagger/swagger.html` locally.

# Configuration

Standard practice is for the repository to be cloned into the directory `/var/fairdata-sso`.

The encrypted package `config.tgz.secret` must be unencrypted and unpacked, creating the
subdirectory `config/` (see below regarding the use of <a href="#git-secret">Git Secret</a>).

Python3 must be installed, and a virtual environment initialized by running the script

    utils/initialize-venv

A configuration file `config.json` must be created, defining the essential configuration
variables for the service.

Configurations exist for the commonly used development, testing, stable, demo, and production
servers, located in the unencrypted and unpacked `config/` subdirectory, and standard practice is
to create a symbolic link `config.json` in the root directory to the appropriate server specific
configuration file in the `config/` subdirectory. In this way, when an updated `config.tgz.secret`
file is unencrypted and unpacked, the symbolic link will point to the same, possibly updated,
configuration file.  

A SAML settings file `saml.json` must be created, defining the essential SAML2 settings for the service.

Settings exist for the commonly used development, testing, stable, demo, and production
servers, located in the unencrypted and unpacked `config/saml/` subdirectory, and standard practice
is to create a symbolic link `saml.json` in the root directory to the appropriate server specific
settings file in the `config/saml/` subdirectory. In this way, when an updated `config.tgz.secret`
file is unencrypted and unpacked, the symbolic link will point to the same, possibly updated,
settings file.

After all of the above is done, setup as a service is done once by running the script

    utils/initialize-service

which also will run the `initialize-venv` script.

The service can be managed using the `systemctl` command. E.g.:

    systemctl status fairdata-sso
    systemctl start fairdata-sso
    systemctl stop fairdata-sso
    systemctl restart fairdata-sso


<a id="git-secret"></a>
# Git Secret

The configuration files, including SAML2 and  wildcard TLS certificates, are encrypted
using Git Secret (https://git-secret.io/) and stored in the encrypted package
file `config.tgz.secret`

Git Secret must be installed on the machine where the git repository is cloned. See the
installation instructions provided at the link above.

To unencrypt and unpack the configuration files, you must first generate and provide your
public GPG key to one of the Fairdata developers who already have access. Once added to
the keychain, and the re-encrypted file is committed to the repo, and pulled locally, execute
the following commands in the root directory:

    git secret tell firstname.lastname@csc.fi
    git secret reveal

This will produce the unencrypted file `config.tgz`. Then execute the command

    tar xzvf config.tgz

which will unpack the configuration files into the `config/` subdirectory.

Finally, create symbolic links in the root directory to the appropriate configuration and settings files (or create new configuration and settings files accordingly):

    ln -s config/sso.fairdata.fi.json config.json
    ln -s config/saml/sso.fairdata.fi.json saml.json

### Updating configuration files

After updating any files in the /config subdirectory, create a new config.tgz file with the command

    tar czvf config.tgz ./config

Then encrypt the new package file with the command

    git secret hide

Then add and commit the updated encrypted package file to the repository

    git add --all
    git commit -m 'Updated configuration ...' 

### Adding a new developer

For a developer who already has Git Secret access, the steps to add a new GPG public key to the keychain for a
new developer are as follows:

Ask the developer for their GPG public key file and the email address it was associated with by having
them execute the following command and sending you the key file produced:

    gpg --export firstname.lastname@csc.fi > firstname.lastname@csc.fi-public.key

Import their public key and then decrypt and re-encrypt the secret files:

    gpg --import firstname.lastname@csc.fi-public.key
    git secret tell firstname.lastname@csc.fi
    git secret reveal
    git secret hide -d

Finally, commit and push the updated files.

### Certificate Management

When updating or creating new TLS certificates, the email recipient should be specified as fairdata-services@postit.csc.fi 

C.f. https://wiki.csc.fi/PATA/Ohjeet/CertificateSigningRequest for instructions


