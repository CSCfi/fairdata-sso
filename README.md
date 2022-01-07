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

# Development with Docker (Linux / Mac)

Repository includes assets for setting up local development environment with
Docker. Follow the instructions below to setup a local development environment
using domain `sso.fd-dev.csc.fi`.

## Prerequisites

These instructions assume that necessary configuration files are available on
the workstation. See section `Docker configs` below.

## Update etc/hosts

Append the following entry to your workstations `/etc/hosts` file:

```
0.0.0.0 sso.fd-dev.csc.fi
```

## Docker image

Docker image can either be built locally or pulled from docker registry. Stack
template uses private registry url, which should be available for internal
development.

If using local images, build the docker image for fairdata-sso by running the
following command at the repository root:

```
docker build --no-cache . -t fairdata-docker.artifactory.ci.csc.fi/fairdata-sso
```

## Docker configs

Once certificates and nginx configuration are available, create needed docker
configs in repository `fairdata-secrets`:

```
docker stack deploy -c sso/docker-compose.dev.yml fairdata-conf
docker stack deploy -c tls/docker-compose.dev.yml fairdata-conf
```

## Docker stack

If not already started, start a new Docker Swarm cluster:

```
docker swarm init
```

Deploy application stack using the previously built image:

```
docker stack deploy --with-registry-auth --resolve-image always -c docker-compose.yml fairdata-sso
```

## Verify installation

Swagger ui for local development environment with the above configuration
should be accessible by visiting [https://sso.fd-dev.csc.fi/](https://sso.fd-dev.csc.fi/).
